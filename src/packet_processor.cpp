#include "packet_processor/packet_processor.h"
#include "packet_processor/capture/packet_capture.h"
#include "packet_processor/processing/thread_pool.h"
#include "packet_processor/processing/zero_copy_buffer.h"
#include "packet_processor/protocol/protocol_parser.h"
#include "packet_processor/protocol/connection_tracker.h"
#include "packet_processor/util/statistics.h"
#include "packet_processor/util/logger.h"

#include <iostream>
#include <chrono>
#include <thread>
#include <vector>
#include <algorithm>

namespace packet_processor {

// Default implementation for batch processing
std::vector<Packet> PacketHandler::handlePacketBatch(const std::vector<Packet>& packets) {
    std::vector<Packet> result;
    result.reserve(packets.size());
    
    for (const auto& packet : packets) {
        if (handlePacket(packet)) {
            result.push_back(packet);
        }
    }
    
    return result;
}

// Constructor
PacketProcessor::PacketProcessor(const PacketProcessorConfig& config)
    : config_(config),
      is_running_(false) {
}

// Destructor
PacketProcessor::~PacketProcessor() {
    // Stop processing if still running
    if (is_running_) {
        stop();
    }
}

// Initialize the packet processor
bool PacketProcessor::initialize() {
    // Create logger first for debugging
    LogLevel log_level = Logger::stringToLevel(config_.log_level);
    logger_ = std::make_unique<Logger>(log_level);
    
    // Log configuration
    logger_->info("Initializing packet processor");
    logger_->info("Device: " + config_.device_name);
    logger_->info("Buffer size: " + std::to_string(config_.capture_buffer_size) + " bytes");
    logger_->info("Zero-copy buffer size: " + std::to_string(config_.zero_copy_buffer_size) + " bytes");
    logger_->info("Ring buffer count: " + std::to_string(config_.ring_buffer_count));
    logger_->info("Processing threads: " + std::to_string(config_.processing_threads) + 
                 (config_.processing_threads == 0 ? " (auto)" : ""));
    
    // Create zero-copy buffer
    logger_->info("Creating zero-copy buffer");
    buffer_ = std::make_unique<ZeroCopyBuffer>(
        config_.zero_copy_buffer_size / config_.ring_buffer_count,
        config_.ring_buffer_count
    );
    
    if (!buffer_->initialize()) {
        logger_->error("Failed to initialize zero-copy buffer");
        return false;
    }
    
    // Create thread pool
    logger_->info("Creating thread pool");
    thread_pool_ = std::make_unique<ThreadPool>(config_.processing_threads);
    
    if (!thread_pool_->initialize()) {
        logger_->error("Failed to initialize thread pool");
        return false;
    }
    
    // Create packet capture
    logger_->info("Creating packet capture");
    capture_ = std::make_unique<PacketCapture>(
        config_.device_name,
        config_.capture_buffer_size,
        config_.snaplen,
        config_.promiscuous_mode,
        buffer_.get()
    );
    
    if (!capture_->initialize()) {
        logger_->error("Failed to initialize packet capture");
        return false;
    }
    
    // Set BPF filter if specified
    if (!config_.bpf_filter.empty()) {
        logger_->info("Setting BPF filter: " + config_.bpf_filter);
        if (!capture_->setFilter(config_.bpf_filter)) {
            logger_->error("Failed to set BPF filter");
            return false;
        }
    }
    
    // Create protocol parser
    logger_->info("Creating protocol parser");
    parser_ = std::make_unique<ProtocolParser>();
    
    // Create connection tracker
    logger_->info("Creating connection tracker");
    tracker_ = std::make_unique<ConnectionTracker>();
    
    // Create statistics
    if (config_.enable_stats) {
        logger_->info("Creating statistics");
        statistics_ = std::make_unique<Statistics>(config_.stats_interval_ms);
    }
    
    logger_->info("Packet processor initialized");
    return true;
}

// Start packet processing
bool PacketProcessor::start() {
    if (is_running_) {
        return true;  // Already running
    }
    
    logger_->info("Starting packet processor");
    
    // Start statistics collection
    if (statistics_) {
        logger_->info("Starting statistics collection");
        statistics_->start();
    }
    
    // Start thread pool
    logger_->info("Starting thread pool with " + 
                 std::to_string(thread_pool_->getThreadCount()) + " threads");
    thread_pool_->start();
    
    // Start packet capture
    logger_->info("Starting packet capture on " + config_.device_name);
    if (!capture_->start()) {
        logger_->error("Failed to start packet capture");
        return false;
    }
    
    // Set running flag
    is_running_ = true;
    
    // Start processing loop in a separate thread
    std::thread process_thread(&PacketProcessor::processingLoop, this);
    process_thread.detach();
    
    logger_->info("Packet processor started");
    return true;
}

// Stop packet processing
void PacketProcessor::stop() {
    if (!is_running_) {
        return;  // Not running
    }
    
    logger_->info("Stopping packet processor");
    
    // Clear running flag
    is_running_ = false;
    
    // Stop packet capture
    logger_->info("Stopping packet capture");
    capture_->stop();
    
    // Stop thread pool
    logger_->info("Stopping thread pool");
    thread_pool_->stop();
    
    // Stop statistics collection
    if (statistics_) {
        logger_->info("Stopping statistics collection");
        statistics_->stop();
    }
    
    logger_->info("Packet processor stopped");
}

// Add a packet handler
void PacketProcessor::addHandler(std::shared_ptr<PacketHandler> handler) {
    handlers_.push_back(handler);
}

// Get current statistics
PacketProcessorStats PacketProcessor::getStatistics() const {
    if (statistics_) {
        return statistics_->getStatistics();
    }
    
    // Return empty statistics if disabled
    return PacketProcessorStats{};
}

// Set statistics callback
void PacketProcessor::setStatisticsCallback(std::function<void(const PacketProcessorStats&)> callback) {
    if (statistics_) {
        statistics_->setUpdateCallback(callback);
    }
}

// Processing loop
void PacketProcessor::processingLoop() {
    logger_->info("Processing loop started");
    
    while (is_running_) {
        // Get a buffer to process
        RingBufferEntry* buffer_entry = buffer_->getReadBuffer();
        if (!buffer_entry) {
            // No buffer available, wait and try again
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            continue;
        }
        
        // Get buffer ID and size
        uint32_t buffer_id = static_cast<uint32_t>(buffer_entry - &buffer_->getReadBuffer());
        uint32_t size = buffer_entry->size;
        
        if (size == 0) {
            // Empty buffer, release it and continue
            buffer_->releaseReadBuffer(buffer_id);
            continue;
        }
        
        // Create a vector of packets to process
        std::vector<Packet> packets;
        
        // Process each packet in the buffer
        uint32_t offset = 0;
        while (offset < size) {
            // Ensure we have at least enough data for packet metadata
            if (offset + sizeof(uint32_t) > size) {
                break;
            }
            
            // Read packet length
            uint32_t packet_length = *reinterpret_cast<uint32_t*>(buffer_entry->data + offset);
            offset += sizeof(uint32_t);
            
            // Ensure we have enough data for the packet
            if (offset + packet_length > size) {
                break;
            }
            
            // Create packet object
            Packet packet;
            packet.data = buffer_entry->data + offset;
            packet.length = packet_length;
            packet.buffer_id = buffer_id;
            
            // Add to batch
            packets.push_back(packet);
            
            // Move to next packet
            offset += packet_length;
        }
        
        // Process the batch of packets
        if (!packets.empty()) {
            processPacketBatch(packets);
        }
        
        // Release the buffer
        buffer_->releaseReadBuffer(buffer_id);
    }
    
    logger_->info("Processing loop stopped");
}

// Process a batch of packets
void PacketProcessor::processPacketBatch(const std::vector<Packet>& packets) {
    // Start timing
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Parse each packet
    std::vector<Packet> parsed_packets;
    parsed_packets.reserve(packets.size());
    
    for (const auto& packet : packets) {
        // Create a copy of the packet for parsing
        Packet parsed_packet = packet;
        
        // Parse protocols
        auto protocols = parser_->parsePacket(parsed_packet);
        
        // Track connection for TCP and UDP
        if (parsed_packet.ip_protocol == IPPROTO_TCP || 
            parsed_packet.ip_protocol == IPPROTO_UDP) {
            tracker_->updateConnection(parsed_packet);
        }
        
        // Add to parsed packets
        parsed_packets.push_back(parsed_packet);
        
        // Update statistics
        if (statistics_) {
            statistics_->recordPacketCapture(parsed_packet.length);
        }
    }
    
    // Process packets through handlers
    std::vector<Packet> current_batch = parsed_packets;
    
    for (auto& handler : handlers_) {
        // Process the batch through this handler
        current_batch = handler->handlePacketBatch(current_batch);
        
        // Stop if no packets remain
        if (current_batch.empty()) {
            break;
        }
    }
    
    // Calculate processing time
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end_time - start_time);
    
    // Update statistics
    if (statistics_) {
        for (const auto& packet : parsed_packets) {
            statistics_->recordPacketProcessing(
                packet.length, 
                duration.count() / parsed_packets.size() // Average time per packet
            );
        }
        
        // Update dropped packets
        CaptureStats capture_stats = capture_->getStatistics();
        statistics_->recordPacketDrops(
            capture_stats.packets_dropped + capture_stats.packets_if_dropped,
            buffer_->getOverflowCount()
        );
    }
}

} // namespace packet_processor 