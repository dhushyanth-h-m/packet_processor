#include "packet_processor/capture/packet_capture.h"
#include "packet_processor/core/zero_copy_buffer.h"
#include "packet_processor/parser/protocol_parser.h"
#include <iostream>
#include <chrono>
#include <thread>
#include <atomic>
#include <csignal>
#include <string>
#include <unordered_map>
#include <iomanip>
#include <getopt.h>

using namespace packet_processor;
using namespace std::chrono;

// Global flag for handling interrupts
std::atomic<bool> running(true);

// Signal handler
void signalHandler(int signal) {
    std::cout << "Received signal " << signal << ", stopping..." << std::endl;
    running = false;
}

// Benchmark statistics
struct BenchmarkStats {
    uint64_t total_packets = 0;
    uint64_t total_bytes = 0;
    uint64_t tcp_packets = 0;
    uint64_t udp_packets = 0;
    uint64_t ipv4_packets = 0;
    uint64_t ipv6_packets = 0;
    uint64_t other_packets = 0;
    
    // Performance metrics
    double packets_per_second = 0.0;
    double bytes_per_second = 0.0;
    double megabits_per_second = 0.0;
    
    // Packet size distribution
    std::unordered_map<int, int> size_distribution;
    
    // Capture stats
    CaptureStats capture_stats = {0};
};

// Print usage information
void printUsage(const char* program) {
    std::cout << "Usage: " << program << " [options]" << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  --interface=<interface>  Network interface to capture (default: en0)" << std::endl;
    std::cout << "  --duration=<seconds>     Duration of benchmark in seconds (default: 30)" << std::endl;
    std::cout << "  --filter=<filter>        BPF filter (default: \"tcp or udp\")" << std::endl;
    std::cout << "  --report-interval=<sec>  Report interval in seconds (default: 1)" << std::endl;
    std::cout << "  --promiscuous            Enable promiscuous mode (default: off)" << std::endl;
    std::cout << "  --help                   Show this help message" << std::endl;
}

// Print benchmark results
void printResults(const BenchmarkStats& stats, double elapsed_seconds) {
    std::cout << "\n==== Benchmark Results ====" << std::endl;
    std::cout << "Duration: " << elapsed_seconds << " seconds" << std::endl;
    
    std::cout << "\nTraffic Statistics:" << std::endl;
    std::cout << "  Total Packets: " << stats.total_packets << std::endl;
    std::cout << "  Total Bytes: " << stats.total_bytes << std::endl;
    std::cout << "  Throughput: " << std::fixed << std::setprecision(2) 
              << stats.packets_per_second << " packets/sec, "
              << stats.megabits_per_second << " Mbps" << std::endl;
    
    std::cout << "\nProtocol Distribution:" << std::endl;
    std::cout << "  IPv4: " << stats.ipv4_packets << " (" 
              << (stats.total_packets > 0 ? (stats.ipv4_packets * 100.0 / stats.total_packets) : 0.0) 
              << "%)" << std::endl;
    std::cout << "  IPv6: " << stats.ipv6_packets << " (" 
              << (stats.total_packets > 0 ? (stats.ipv6_packets * 100.0 / stats.total_packets) : 0.0) 
              << "%)" << std::endl;
    std::cout << "  TCP: " << stats.tcp_packets << " (" 
              << (stats.total_packets > 0 ? (stats.tcp_packets * 100.0 / stats.total_packets) : 0.0) 
              << "%)" << std::endl;
    std::cout << "  UDP: " << stats.udp_packets << " (" 
              << (stats.total_packets > 0 ? (stats.udp_packets * 100.0 / stats.total_packets) : 0.0) 
              << "%)" << std::endl;
    std::cout << "  Other: " << stats.other_packets << " (" 
              << (stats.total_packets > 0 ? (stats.other_packets * 100.0 / stats.total_packets) : 0.0) 
              << "%)" << std::endl;
    
    std::cout << "\nCapture Performance:" << std::endl;
    std::cout << "  Packets Captured: " << stats.capture_stats.packets_captured << std::endl;
    std::cout << "  Packets Dropped: " << stats.capture_stats.packets_dropped << " (" 
              << (stats.capture_stats.packets_captured > 0 ? 
                 (stats.capture_stats.packets_dropped * 100.0 / stats.capture_stats.packets_captured) : 0.0) 
              << "%)" << std::endl;
    std::cout << "  Interface Dropped: " << stats.capture_stats.packets_if_dropped << std::endl;
    
    if (!stats.size_distribution.empty()) {
        std::cout << "\nPacket Size Distribution:" << std::endl;
        // Group by size ranges
        int small_packets = 0;    // 0-128 bytes
        int medium_packets = 0;   // 129-512 bytes
        int large_packets = 0;    // 513-1024 bytes
        int jumbo_packets = 0;    // 1025+ bytes
        
        for (const auto& entry : stats.size_distribution) {
            if (entry.first <= 128) {
                small_packets += entry.second;
            } else if (entry.first <= 512) {
                medium_packets += entry.second;
            } else if (entry.first <= 1024) {
                large_packets += entry.second;
            } else {
                jumbo_packets += entry.second;
            }
        }
        
        std::cout << "  Small (0-128 bytes): " << small_packets << " (" 
                  << (stats.total_packets > 0 ? (small_packets * 100.0 / stats.total_packets) : 0.0) 
                  << "%)" << std::endl;
        std::cout << "  Medium (129-512 bytes): " << medium_packets << " (" 
                  << (stats.total_packets > 0 ? (medium_packets * 100.0 / stats.total_packets) : 0.0) 
                  << "%)" << std::endl;
        std::cout << "  Large (513-1024 bytes): " << large_packets << " (" 
                  << (stats.total_packets > 0 ? (large_packets * 100.0 / stats.total_packets) : 0.0) 
                  << "%)" << std::endl;
        std::cout << "  Jumbo (1025+ bytes): " << jumbo_packets << " (" 
                  << (stats.total_packets > 0 ? (jumbo_packets * 100.0 / stats.total_packets) : 0.0) 
                  << "%)" << std::endl;
    }
}

int main(int argc, char* argv[]) {
    // Set signal handler
    std::signal(SIGINT, signalHandler);
    
    // Default options
    std::string device_name = "en0";
    std::string filter = "tcp or udp";
    bool promiscuous = false;
    int duration_seconds = 30;
    int report_interval = 1;
    
    // Parse command-line options
    static struct option long_options[] = {
        {"interface", required_argument, 0, 'i'},
        {"duration", required_argument, 0, 'd'},
        {"filter", required_argument, 0, 'f'},
        {"report-interval", required_argument, 0, 'r'},
        {"promiscuous", no_argument, 0, 'p'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    int option_index = 0;
    int c;
    
    while ((c = getopt_long(argc, argv, "i:d:f:r:ph", long_options, &option_index)) != -1) {
        switch (c) {
            case 'i':
                device_name = optarg;
                break;
            case 'd':
                duration_seconds = std::stoi(optarg);
                break;
            case 'f':
                filter = optarg;
                break;
            case 'r':
                report_interval = std::stoi(optarg);
                break;
            case 'p':
                promiscuous = true;
                break;
            case 'h':
                printUsage(argv[0]);
                return 0;
            default:
                printUsage(argv[0]);
                return 1;
        }
    }
    
    std::cout << "=== Packet Processing Benchmark ===" << std::endl;
    std::cout << "Interface: " << device_name << std::endl;
    std::cout << "Duration: " << duration_seconds << " seconds" << std::endl;
    std::cout << "Filter: " << filter << std::endl;
    std::cout << "Report Interval: " << report_interval << " seconds" << std::endl;
    std::cout << "Promiscuous Mode: " << (promiscuous ? "Yes" : "No") << std::endl;
    
    // Create zero-copy buffer
    const uint32_t buffer_count = 256;  // More buffers for benchmarking
    const uint32_t buffer_size = 65536; // Larger buffer size
    ZeroCopyBuffer buffer(buffer_count, buffer_size);
    
    // Create packet capture
    const int pcap_buffer_size = 32 * 1024 * 1024;  // 32MB buffer for high throughput
    const int snaplen = 65535;  // Maximum packet size
    
    PacketCapture capture(device_name, pcap_buffer_size, snaplen, promiscuous, &buffer);
    
    // Initialize capture
    if (!capture.initialize()) {
        std::cerr << "Failed to initialize packet capture" << std::endl;
        return 1;
    }
    
    // Set filter
    if (!capture.setFilter(filter)) {
        std::cerr << "Failed to set filter" << std::endl;
        return 1;
    }
    
    // Create protocol parser
    ProtocolParser parser;
    
    // Start capture
    if (!capture.start()) {
        std::cerr << "Failed to start packet capture" << std::endl;
        return 1;
    }
    
    std::cout << "\nBenchmark started. Press Ctrl+C to stop early." << std::endl;
    
    // Statistics
    BenchmarkStats stats;
    auto start_time = steady_clock::now();
    auto last_report_time = start_time;
    
    // Process packets until duration is reached or interrupted
    while (running) {
        auto now = steady_clock::now();
        auto elapsed = duration_cast<seconds>(now - start_time).count();
        
        // Check if benchmark duration has been reached
        if (elapsed >= duration_seconds) {
            break;
        }
        
        // Get a buffer with captured packets
        RingBufferEntry* buffer_entry = buffer.getReadBuffer();
        if (!buffer_entry) {
            // No packets available, wait and try again
            std::this_thread::sleep_for(milliseconds(1));
            continue;
        }
        
        // Process packets in the buffer
        const uint8_t* data = buffer_entry->data;
        uint32_t size = buffer_entry->size;
        
        // Create packet structure
        Packet packet;
        packet.data = data;
        packet.length = size;
        
        // Parse packet
        if (parser.parsePacket(packet)) {
            // Update protocol statistics
            if (packet.ip_version == 4) {
                stats.ipv4_packets++;
            } else if (packet.ip_version == 6) {
                stats.ipv6_packets++;
            } else {
                stats.other_packets++;
            }
            
            if (packet.ip_protocol == static_cast<uint8_t>(IPProtocol::TCP)) {
                stats.tcp_packets++;
            } else if (packet.ip_protocol == static_cast<uint8_t>(IPProtocol::UDP)) {
                stats.udp_packets++;
            } else {
                stats.other_packets++;
            }
            
            // Update size distribution
            stats.size_distribution[packet.length]++;
        }
        
        // Update statistics
        stats.total_packets++;
        stats.total_bytes += size;
        
        // Release the buffer
        buffer.releaseReadBuffer(buffer_entry - buffer.getBuffers());
        
        // Print periodic report
        auto report_elapsed = duration_cast<seconds>(now - last_report_time).count();
        if (report_elapsed >= report_interval) {
            // Get capture statistics
            stats.capture_stats = capture.getStatistics();
            
            // Calculate performance metrics
            stats.packets_per_second = static_cast<double>(stats.total_packets) / elapsed;
            stats.bytes_per_second = static_cast<double>(stats.total_bytes) / elapsed;
            stats.megabits_per_second = (stats.bytes_per_second * 8) / 1000000.0;
            
            // Print report
            std::cout << "\rElapsed: " << elapsed << "s, "
                      << "Packets: " << stats.total_packets 
                      << " (" << std::fixed << std::setprecision(2) << stats.packets_per_second << " pps), "
                      << "Throughput: " << std::fixed << std::setprecision(2) << stats.megabits_per_second << " Mbps"
                      << std::flush;
            
            last_report_time = now;
        }
    }
    
    // Stop capture
    capture.stop();
    
    // Get final capture statistics
    stats.capture_stats = capture.getStatistics();
    
    // Calculate final performance metrics
    auto end_time = steady_clock::now();
    auto elapsed_seconds = duration_cast<duration<double>>(end_time - start_time).count();
    stats.packets_per_second = static_cast<double>(stats.total_packets) / elapsed_seconds;
    stats.bytes_per_second = static_cast<double>(stats.total_bytes) / elapsed_seconds;
    stats.megabits_per_second = (stats.bytes_per_second * 8) / 1000000.0;
    
    std::cout << "\nBenchmark completed." << std::endl;
    
    // Print benchmark results
    printResults(stats, elapsed_seconds);
    
    return 0;
} 