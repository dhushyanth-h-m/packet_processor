#pragma once

#include <cstdint>
#include <atomic>
#include <chrono>
#include <vector>
#include <mutex>
#include <thread>
#include <functional>
#include "../packet_processor.h"

namespace packet_processor {

/**
 * @brief Performance statistics calculator
 * 
 * This class collects and calculates performance statistics for the packet
 * processing engine, including throughput, packet rates, and CPU utilization.
 */
class Statistics {
public:
    /**
     * @brief Construct a new Statistics object
     * 
     * @param update_interval_ms Interval in milliseconds for statistics updates
     */
    explicit Statistics(int update_interval_ms = 1000);
    
    /**
     * @brief Destructor
     */
    ~Statistics();
    
    /**
     * @brief Start collecting statistics
     */
    void start();
    
    /**
     * @brief Stop collecting statistics
     */
    void stop();
    
    /**
     * @brief Record a packet capture
     * 
     * @param packet_size Size of the packet in bytes
     */
    void recordPacketCapture(uint32_t packet_size);
    
    /**
     * @brief Record a packet processing
     * 
     * @param packet_size Size of the packet in bytes
     * @param processing_time_ns Processing time in nanoseconds
     */
    void recordPacketProcessing(uint32_t packet_size, uint64_t processing_time_ns);
    
    /**
     * @brief Record packet drops
     * 
     * @param pcap_drops Packets dropped by libpcap
     * @param buffer_drops Packets dropped due to full buffer
     */
    void recordPacketDrops(uint64_t pcap_drops, uint64_t buffer_drops);
    
    /**
     * @brief Get current statistics
     * 
     * @return PacketProcessorStats structure with current statistics
     */
    PacketProcessorStats getStatistics() const;
    
    /**
     * @brief Reset all statistics
     */
    void reset();
    
    /**
     * @brief Set a callback function to call when statistics are updated
     * 
     * @param callback Function to call with updated statistics
     */
    void setUpdateCallback(std::function<void(const PacketProcessorStats&)> callback);
    
private:
    int update_interval_ms_;
    
    // Core statistics counters
    std::atomic<uint64_t> packets_captured_;
    std::atomic<uint64_t> packets_processed_;
    std::atomic<uint64_t> packets_dropped_pcap_;
    std::atomic<uint64_t> packets_dropped_buffer_;
    std::atomic<uint64_t> bytes_processed_;
    std::atomic<uint64_t> processing_time_ns_total_;
    
    // Derived statistics
    double packets_per_second_;
    double mbps_;
    double cpu_usage_;
    uint64_t avg_processing_ns_;
    
    // Tracking timestamps
    std::chrono::steady_clock::time_point last_update_time_;
    
    // History for rate calculations
    struct HistoryEntry {
        uint64_t packets_captured;
        uint64_t bytes_processed;
        std::chrono::steady_clock::time_point timestamp;
    };
    
    static constexpr size_t HISTORY_SIZE = 10;
    std::vector<HistoryEntry> history_;
    mutable std::mutex history_mutex_;
    
    // Update thread
    std::thread update_thread_;
    std::atomic<bool> running_;
    
    // Callback function
    std::function<void(const PacketProcessorStats&)> update_callback_;
    
    /**
     * @brief Update thread function
     */
    void updateLoop();
    
    /**
     * @brief Calculate current statistics
     */
    void calculateStatistics();
    
    /**
     * @brief Measure current CPU usage
     * 
     * @return CPU usage as a percentage (0-100)
     */
    double measureCpuUsage() const;
};

} // namespace packet_processor 