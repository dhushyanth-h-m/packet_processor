#include "packet_processor/util/statistics.h"
#include <algorithm>
#include <numeric>
#include <thread>
#include <iostream>

#ifdef __APPLE__
#include <mach/mach.h>
#include <mach/mach_host.h>
#include <mach/task_info.h>
#include <mach/task.h>
#include <mach/vm_map.h>
#include <sys/sysctl.h>
#endif

namespace packet_processor {

Statistics::Statistics(int update_interval_ms)
    : update_interval_ms_(update_interval_ms),
      packets_captured_(0),
      packets_processed_(0),
      packets_dropped_pcap_(0),
      packets_dropped_buffer_(0),
      bytes_processed_(0),
      processing_time_ns_total_(0),
      packets_per_second_(0),
      mbps_(0),
      cpu_usage_(0),
      avg_processing_ns_(0),
      running_(false) {
    
    // Initialize history with zero entries
    history_.resize(HISTORY_SIZE);
    for (auto& entry : history_) {
        entry.packets_captured = 0;
        entry.bytes_processed = 0;
        entry.timestamp = std::chrono::steady_clock::now();
    }
}

Statistics::~Statistics() {
    stop();
}

void Statistics::start() {
    if (running_) {
        return;
    }
    
    // Reset statistics
    reset();
    
    // Set running flag
    running_ = true;
    
    // Start update thread
    update_thread_ = std::thread(&Statistics::updateLoop, this);
}

void Statistics::stop() {
    if (!running_) {
        return;
    }
    
    // Clear running flag
    running_ = false;
    
    // Wait for update thread to finish
    if (update_thread_.joinable()) {
        update_thread_.join();
    }
}

void Statistics::recordPacketCapture(uint32_t packet_size) {
    packets_captured_++;
    bytes_processed_ += packet_size;
}

void Statistics::recordPacketProcessing(uint32_t packet_size, uint64_t processing_time_ns) {
    packets_processed_++;
    processing_time_ns_total_ += processing_time_ns;
}

void Statistics::recordPacketDrops(uint64_t pcap_drops, uint64_t buffer_drops) {
    packets_dropped_pcap_ = pcap_drops;
    packets_dropped_buffer_ = buffer_drops;
}

PacketProcessorStats Statistics::getStatistics() const {
    PacketProcessorStats stats;
    stats.packets_captured = packets_captured_;
    stats.packets_processed = packets_processed_;
    stats.packets_dropped_pcap = packets_dropped_pcap_;
    stats.packets_dropped_buffer = packets_dropped_buffer_;
    stats.bytes_processed = bytes_processed_;
    stats.packets_per_second = packets_per_second_;
    stats.mbps = mbps_;
    stats.cpu_usage = cpu_usage_;
    stats.avg_processing_ns = avg_processing_ns_;
    
    return stats;
}

void Statistics::reset() {
    packets_captured_ = 0;
    packets_processed_ = 0;
    packets_dropped_pcap_ = 0;
    packets_dropped_buffer_ = 0;
    bytes_processed_ = 0;
    processing_time_ns_total_ = 0;
    packets_per_second_ = 0;
    mbps_ = 0;
    cpu_usage_ = 0;
    avg_processing_ns_ = 0;
    
    // Reset history
    std::lock_guard<std::mutex> lock(history_mutex_);
    for (auto& entry : history_) {
        entry.packets_captured = 0;
        entry.bytes_processed = 0;
        entry.timestamp = std::chrono::steady_clock::now();
    }
    
    last_update_time_ = std::chrono::steady_clock::now();
}

void Statistics::setUpdateCallback(std::function<void(const PacketProcessorStats&)> callback) {
    update_callback_ = callback;
}

void Statistics::updateLoop() {
    while (running_) {
        // Wait for the specified interval
        std::this_thread::sleep_for(std::chrono::milliseconds(update_interval_ms_));
        
        // Calculate statistics
        calculateStatistics();
        
        // Call the update callback if set
        if (update_callback_) {
            update_callback_(getStatistics());
        }
    }
}

void Statistics::calculateStatistics() {
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_update_time_).count();
    
    if (elapsed <= 0) {
        return;  // Avoid division by zero
    }
    
    // Update history
    {
        std::lock_guard<std::mutex> lock(history_mutex_);
        
        // Shift history entries
        for (size_t i = HISTORY_SIZE - 1; i > 0; --i) {
            history_[i] = history_[i - 1];
        }
        
        // Add new entry
        history_[0].packets_captured = packets_captured_;
        history_[0].bytes_processed = bytes_processed_;
        history_[0].timestamp = now;
    }
    
    // Calculate packets per second
    if (history_.size() >= 2) {
        uint64_t packet_diff = history_[0].packets_captured - history_[1].packets_captured;
        auto time_diff = std::chrono::duration_cast<std::chrono::milliseconds>(
            history_[0].timestamp - history_[1].timestamp).count();
        
        if (time_diff > 0) {
            packets_per_second_ = static_cast<double>(packet_diff) * 1000.0 / time_diff;
        }
    }
    
    // Calculate Mbps
    if (history_.size() >= 2) {
        uint64_t byte_diff = history_[0].bytes_processed - history_[1].bytes_processed;
        auto time_diff = std::chrono::duration_cast<std::chrono::milliseconds>(
            history_[0].timestamp - history_[1].timestamp).count();
        
        if (time_diff > 0) {
            // Convert to Mbps (bytes to bits, and per second)
            mbps_ = static_cast<double>(byte_diff) * 8.0 / 1000000.0 * 1000.0 / time_diff;
        }
    }
    
    // Calculate average processing time
    if (packets_processed_ > 0) {
        avg_processing_ns_ = processing_time_ns_total_ / packets_processed_;
    } else {
        avg_processing_ns_ = 0;
    }
    
    // Calculate CPU usage
    cpu_usage_ = measureCpuUsage();
    
    // Update timestamp
    last_update_time_ = now;
}

double Statistics::measureCpuUsage() const {
#ifdef __APPLE__
    // On macOS, get CPU usage for the current process
    task_info_data_t task_info_data;
    mach_msg_type_number_t task_info_count = TASK_INFO_MAX;
    
    if (task_info(mach_task_self(), TASK_BASIC_INFO, 
                 (task_info_t)task_info_data, &task_info_count) != KERN_SUCCESS) {
        return 0.0;
    }
    
    task_basic_info_t basic_info = (task_basic_info_t)task_info_data;
    
    thread_array_t thread_list;
    mach_msg_type_number_t thread_count;
    
    if (task_threads(mach_task_self(), &thread_list, &thread_count) != KERN_SUCCESS) {
        return 0.0;
    }
    
    double total_cpu = 0.0;
    for (unsigned int i = 0; i < thread_count; ++i) {
        thread_info_data_t thread_info_data;
        mach_msg_type_number_t thread_info_count = THREAD_INFO_MAX;
        
        if (thread_info(thread_list[i], THREAD_BASIC_INFO, 
                       (thread_info_t)thread_info_data, &thread_info_count) != KERN_SUCCESS) {
            continue;
        }
        
        thread_basic_info_t thread_basic_info = (thread_basic_info_t)thread_info_data;
        
        if (!(thread_basic_info->flags & TH_FLAGS_IDLE)) {
            total_cpu += thread_basic_info->cpu_usage / (float)TH_USAGE_SCALE * 100.0;
        }
    }
    
    // Clean up
    vm_deallocate(mach_task_self(), (vm_address_t)thread_list, 
                 thread_count * sizeof(thread_t));
    
    return total_cpu;
#else
    // Not implemented for other platforms
    return 0.0;
#endif
}

} // namespace packet_processor 