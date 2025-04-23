#include "packet_processor/packet_processor.h"
#include <iostream>
#include <iomanip>
#include <string>
#include <csignal>
#include <chrono>
#include <thread>

// Global flag for controlling the main loop
static bool running = true;

// Signal handler for graceful shutdown
void signalHandler(int signal) {
    if (signal == SIGINT || signal == SIGTERM) {
        std::cout << "\nShutting down..." << std::endl;
        running = false;
    }
}

// Statistics callback function
void printStatistics(const packet_processor::PacketProcessorStats& stats) {
    // Clear the console
    std::cout << "\033[2J\033[1;1H";
    
    // Print statistics header
    std::cout << "======== Basic Packet Capture Example ========" << std::endl;
    std::cout << std::endl;
    
    // Print capture statistics
    std::cout << std::fixed << std::setprecision(2);
    std::cout << "Packets captured:      " << stats.packets_captured << std::endl;
    std::cout << "Packets processed:     " << stats.packets_processed << std::endl;
    std::cout << "Packets dropped (pcap): " << stats.packets_dropped_pcap << std::endl;
    std::cout << "Packets dropped (buf):  " << stats.packets_dropped_buffer << std::endl;
    std::cout << "Total bytes processed: " << stats.bytes_processed << " bytes" << std::endl;
    std::cout << std::endl;
    
    // Print performance statistics
    std::cout << "Current throughput:    " << stats.packets_per_second << " pps / " 
              << stats.mbps << " Mbps" << std::endl;
    std::cout << "CPU usage:             " << stats.cpu_usage << "%" << std::endl;
    std::cout << "Avg processing time:   " << stats.avg_processing_ns << " ns/packet" << std::endl;
    std::cout << std::endl;
    
    // Print footer
    std::cout << "Press Ctrl+C to exit" << std::endl;
}

// Custom packet handler that counts packets by protocol
class ProtocolCounterHandler : public packet_processor::PacketHandler {
public:
    ProtocolCounterHandler() {
        // Initialize counters
        tcp_packets_ = 0;
        udp_packets_ = 0;
        icmp_packets_ = 0;
        other_packets_ = 0;
        
        // Start display thread
        display_thread_ = std::thread(&ProtocolCounterHandler::displayLoop, this);
    }
    
    ~ProtocolCounterHandler() {
        // Signal thread to stop
        running_ = false;
        
        // Wait for thread to finish
        if (display_thread_.joinable()) {
            display_thread_.join();
        }
    }
    
    bool handlePacket(const packet_processor::Packet& packet) override {
        // Count packet by protocol
        if (packet.ip_protocol == IPPROTO_TCP) {
            tcp_packets_++;
        } else if (packet.ip_protocol == IPPROTO_UDP) {
            udp_packets_++;
        } else if (packet.ip_protocol == IPPROTO_ICMP || packet.ip_protocol == IPPROTO_ICMPV6) {
            icmp_packets_++;
        } else {
            other_packets_++;
        }
        
        // Always continue processing
        return true;
    }
    
private:
    std::atomic<uint64_t> tcp_packets_;
    std::atomic<uint64_t> udp_packets_;
    std::atomic<uint64_t> icmp_packets_;
    std::atomic<uint64_t> other_packets_;
    
    std::thread display_thread_;
    std::atomic<bool> running_{true};
    
    void displayLoop() {
        while (running_) {
            // Sleep for 1 second
            std::this_thread::sleep_for(std::chrono::seconds(1));
            
            // Update the display at the bottom of the screen
            std::cout << "\033[s";  // Save cursor position
            std::cout << "\033[20;0H";  // Move to line 20
            
            // Print protocol breakdown
            std::cout << "Protocol breakdown:" << std::endl;
            std::cout << "  TCP:   " << tcp_packets_ << std::endl;
            std::cout << "  UDP:   " << udp_packets_ << std::endl;
            std::cout << "  ICMP:  " << icmp_packets_ << std::endl;
            std::cout << "  Other: " << other_packets_ << std::endl;
            
            std::cout << "\033[u";  // Restore cursor position
            std::cout.flush();
        }
    }
};

int main(int argc, char* argv[]) {
    // Register signal handlers
    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);
    
    // Check command-line arguments
    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " <interface> [filter]" << std::endl;
        std::cout << "Example: " << argv[0] << " en0 \"tcp port 80\"" << std::endl;
        
        // Print available interfaces
        std::cout << "\nAvailable interfaces:" << std::endl;
        auto interfaces = packet_processor::PacketCapture::getDeviceNames();
        for (const auto& interface : interfaces) {
            std::cout << "  - " << interface << std::endl;
        }
        
        return 1;
    }
    
    // Get interface name from command-line arguments
    std::string interface = argv[1];
    
    // Get optional BPF filter from command-line arguments
    std::string filter = (argc > 2) ? argv[2] : "";
    
    // Create packet processor configuration
    packet_processor::PacketProcessorConfig config;
    config.device_name = interface;
    config.capture_buffer_size = 16 * 1024 * 1024;  // 16 MB (larger for high-throughput)
    config.zero_copy_buffer_size = 32 * 1024 * 1024;  // 32 MB
    config.ring_buffer_count = 16;  // More buffers for high-throughput
    config.processing_threads = 0;  // Auto-detect
    config.bpf_filter = filter;
    config.promiscuous_mode = true;
    config.enable_stats = true;
    config.stats_interval_ms = 1000;  // Update stats every second
    config.log_level = "info";
    
    // Create packet processor
    packet_processor::PacketProcessor processor(config);
    
    // Register statistics callback
    processor.setStatisticsCallback(printStatistics);
    
    // Create custom packet handler
    auto handler = std::make_shared<ProtocolCounterHandler>();
    processor.addHandler(handler);
    
    // Initialize processor
    std::cout << "Initializing packet processor on interface " << interface << "..." << std::endl;
    if (!processor.initialize()) {
        std::cerr << "Failed to initialize packet processor" << std::endl;
        return 1;
    }
    
    // Start processor
    std::cout << "Starting packet capture..." << std::endl;
    if (!processor.start()) {
        std::cerr << "Failed to start packet processor" << std::endl;
        return 1;
    }
    
    std::cout << "Packet capture started on interface " << interface << std::endl;
    if (!filter.empty()) {
        std::cout << "Using filter: " << filter << std::endl;
    }
    std::cout << "Press Ctrl+C to exit" << std::endl;
    
    // Main loop
    while (running) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    // Stop processor
    std::cout << "Stopping packet processor..." << std::endl;
    processor.stop();
    
    std::cout << "Packet processor stopped" << std::endl;
    return 0;
} 