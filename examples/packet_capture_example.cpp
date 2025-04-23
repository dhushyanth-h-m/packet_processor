#include "packet_processor/capture/packet_capture.h"
#include "packet_processor/core/zero_copy_buffer.h"
#include "packet_processor/parser/protocol_parser.h"
#include <iostream>
#include <csignal>
#include <chrono>
#include <thread>
#include <atomic>
#include <iomanip>

using namespace packet_processor;

// Global flag for handling interrupts
std::atomic<bool> running(true);

// Signal handler
void signalHandler(int signal) {
    std::cout << "Received signal " << signal << ", stopping..." << std::endl;
    running = false;
}

int main(int argc, char* argv[]) {
    // Set signal handler
    std::signal(SIGINT, signalHandler);
    
    // Get device name from command line or use default
    std::string device_name = "en0";  // Default for macOS
    if (argc > 1) {
        device_name = argv[1];
    }
    
    // Get filter from command line or use default
    std::string filter = "tcp or udp";  // Default filter
    if (argc > 2) {
        filter = argv[2];
    }
    
    std::cout << "Starting packet capture on device " << device_name << std::endl;
    std::cout << "Using filter: " << filter << std::endl;
    
    // Create zero-copy buffer
    const uint32_t buffer_count = 64;
    const uint32_t buffer_size = 16384;
    ZeroCopyBuffer buffer(buffer_count, buffer_size);
    
    // Create packet capture
    const int pcap_buffer_size = 2 * 1024 * 1024;  // 2MB buffer
    const int snaplen = 65535;  // Maximum packet size
    const bool promiscuous = true;  // Capture all packets
    
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
    
    std::cout << "Packet capture started. Press Ctrl+C to stop." << std::endl;
    
    // Statistics
    uint64_t total_packets = 0;
    uint64_t total_bytes = 0;
    auto start_time = std::chrono::steady_clock::now();
    
    // Processing loop
    while (running) {
        // Get a buffer with captured packets
        RingBufferEntry* buffer_entry = buffer.getReadBuffer();
        if (!buffer_entry) {
            // No packets available, wait and try again
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            continue;
        }
        
        // Process packets in the buffer
        const uint8_t* data = buffer_entry->data;
        uint32_t size = buffer_entry->size;
        
        // Print packet information
        std::cout << "Packet: " << total_packets << ", Size: " << size << " bytes" << std::endl;
        
        // Create packet structure
        Packet packet;
        packet.data = data;
        packet.length = size;
        
        // Parse packet
        if (parser.parsePacket(packet)) {
            // Print protocol information
            std::cout << "  EtherType: 0x" << std::hex << std::setw(4) << std::setfill('0') 
                      << packet.eth_type << std::dec << std::endl;
            
            if (packet.ip_version == 4 || packet.ip_version == 6) {
                std::cout << "  IP Version: " << static_cast<int>(packet.ip_version) << std::endl;
                std::cout << "  IP Protocol: " << static_cast<int>(packet.ip_protocol) << std::endl;
                std::cout << "  Source IP: " << ProtocolParser::ipToString(packet.ip_src) << std::endl;
                std::cout << "  Destination IP: " << ProtocolParser::ipToString(packet.ip_dst) << std::endl;
                
                if (packet.ip_protocol == static_cast<uint8_t>(IPProtocol::TCP) || 
                    packet.ip_protocol == static_cast<uint8_t>(IPProtocol::UDP)) {
                    std::cout << "  Source Port: " << packet.port_src << std::endl;
                    std::cout << "  Destination Port: " << packet.port_dst << std::endl;
                    
                    if (packet.ip_protocol == static_cast<uint8_t>(IPProtocol::TCP)) {
                        std::cout << "  TCP Flags: 0x" << std::hex << static_cast<int>(packet.tcp_flags) 
                                  << std::dec << std::endl;
                    }
                }
            }
        }
        
        // Update statistics
        total_packets++;
        total_bytes += size;
        
        // Release the buffer
        buffer.releaseReadBuffer(buffer_entry - buffer.getBuffers());
        
        // Print statistics every second
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - start_time).count();
        if (elapsed >= 1) {
            double pps = static_cast<double>(total_packets) / elapsed;
            double bps = static_cast<double>(total_bytes * 8) / elapsed;
            
            std::cout << "Packets: " << total_packets 
                      << " (" << std::fixed << std::setprecision(2) << pps << " pps), "
                      << "Bytes: " << total_bytes 
                      << " (" << std::fixed << std::setprecision(2) << bps / 1000000.0 << " Mbps)" 
                      << std::endl;
            
            // Get capture statistics
            CaptureStats stats = capture.getStatistics();
            std::cout << "Capture stats - Received: " << stats.packets_captured 
                      << ", Dropped: " << stats.packets_dropped 
                      << ", Interface dropped: " << stats.packets_if_dropped 
                      << std::endl;
        }
    }
    
    // Stop capture
    capture.stop();
    
    std::cout << "Packet capture stopped" << std::endl;
    
    return 0;
} 