#include "packet_processor/packet_processor.h"
#include "packet_processor/protocol/connection_tracker.h"
#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <chrono>
#include <thread>
#include <mutex>
#include <csignal>
#include <arpa/inet.h>

// Global flag for controlling the main loop
static bool running = true;

// Signal handler for graceful shutdown
void signalHandler(int signal) {
    if (signal == SIGINT || signal == SIGTERM) {
        std::cout << "\nShutting down connection monitor..." << std::endl;
        running = false;
    }
}

// Convert a numeric IP address to a string
std::string ipToString(uint32_t ip) {
    struct in_addr addr;
    addr.s_addr = htonl(ip);
    return inet_ntoa(addr);
}

// Get protocol name from IP protocol number
std::string getProtocolName(uint8_t protocol) {
    switch (protocol) {
        case IPPROTO_TCP:
            return "TCP";
        case IPPROTO_UDP:
            return "UDP";
        case IPPROTO_ICMP:
            return "ICMP";
        case IPPROTO_ICMPV6:
            return "ICMPv6";
        default:
            return "Other";
    }
}

// Get connection state as string
std::string getConnectionState(packet_processor::ConnectionState state) {
    switch (state) {
        case packet_processor::ConnectionState::NEW:
            return "NEW";
        case packet_processor::ConnectionState::SYN_SENT:
            return "SYN_SENT";
        case packet_processor::ConnectionState::SYN_RECEIVED:
            return "SYN_RECEIVED";
        case packet_processor::ConnectionState::ESTABLISHED:
            return "ESTABLISHED";
        case packet_processor::ConnectionState::FIN_WAIT_1:
            return "FIN_WAIT_1";
        case packet_processor::ConnectionState::FIN_WAIT_2:
            return "FIN_WAIT_2";
        case packet_processor::ConnectionState::CLOSE_WAIT:
            return "CLOSE_WAIT";
        case packet_processor::ConnectionState::CLOSING:
            return "CLOSING";
        case packet_processor::ConnectionState::LAST_ACK:
            return "LAST_ACK";
        case packet_processor::ConnectionState::TIME_WAIT:
            return "TIME_WAIT";
        case packet_processor::ConnectionState::CLOSED:
            return "CLOSED";
        default:
            return "UNKNOWN";
    }
}

// Connection monitor packet handler
class ConnectionMonitorHandler : public packet_processor::PacketHandler {
public:
    ConnectionMonitorHandler() 
        : display_thread_(&ConnectionMonitorHandler::displayLoop, this),
          running_(true) {}
    
    ~ConnectionMonitorHandler() {
        running_ = false;
        if (display_thread_.joinable()) {
            display_thread_.join();
        }
    }
    
    bool handlePacket(const packet_processor::Packet& packet) override {
        // Only process TCP and UDP packets
        if (packet.ip_protocol != IPPROTO_TCP && packet.ip_protocol != IPPROTO_UDP) {
            return true;
        }
        
        // Create a connection record
        ConnectionKey key = {
            packet.ip_src,
            packet.ip_dst,
            packet.port_src,
            packet.port_dst,
            packet.ip_protocol
        };
        
        // Normalize the key (always use the lower IP/port as source)
        normalizeKey(key);
        
        // Update connection record
        {
            std::lock_guard<std::mutex> lock(mutex_);
            
            auto it = connections_.find(key);
            if (it == connections_.end()) {
                // New connection
                ConnectionData data;
                data.last_seen = std::chrono::steady_clock::now();
                data.packets = 1;
                data.bytes = packet.length;
                data.state = (packet.ip_protocol == IPPROTO_TCP) ? 
                            getConnectionState(packet_processor::ConnectionState::NEW) : "N/A";
                connections_[key] = data;
            } else {
                // Update existing connection
                it->second.last_seen = std::chrono::steady_clock::now();
                it->second.packets++;
                it->second.bytes += packet.length;
                
                // Update state for TCP connections
                if (packet.ip_protocol == IPPROTO_TCP) {
                    // This is a simplified state tracking based on TCP flags
                    uint8_t flags = packet.tcp_flags;
                    bool has_syn = (flags & packet_processor::TCPFlags::SYN) != 0;
                    bool has_fin = (flags & packet_processor::TCPFlags::FIN) != 0;
                    bool has_rst = (flags & packet_processor::TCPFlags::RST) != 0;
                    
                    if (has_rst) {
                        it->second.state = "CLOSED";
                    } else if (has_fin) {
                        it->second.state = "CLOSING";
                    } else if (has_syn) {
                        it->second.state = "SYN_SENT";
                    } else if (it->second.state == "SYN_SENT") {
                        it->second.state = "ESTABLISHED";
                    }
                }
            }
        }
        
        return true;
    }
    
    // Get a snapshot of the current connections
    std::map<ConnectionKey, ConnectionData> getConnections() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return connections_;
    }
    
    // Get the number of connections
    size_t getConnectionCount() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return connections_.size();
    }
    
    // Clean up expired connections
    void cleanupExpiredConnections(uint64_t timeout_ms) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        auto now = std::chrono::steady_clock::now();
        auto it = connections_.begin();
        while (it != connections_.end()) {
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                now - it->second.last_seen).count();
            
            if (elapsed > timeout_ms) {
                it = connections_.erase(it);
            } else {
                ++it;
            }
        }
    }
    
private:
    // Key for identifying a connection
    struct ConnectionKey {
        uint32_t src_ip;
        uint32_t dst_ip;
        uint16_t src_port;
        uint16_t dst_port;
        uint8_t protocol;
        
        bool operator<(const ConnectionKey& other) const {
            if (src_ip != other.src_ip) return src_ip < other.src_ip;
            if (dst_ip != other.dst_ip) return dst_ip < other.dst_ip;
            if (src_port != other.src_port) return src_port < other.src_port;
            if (dst_port != other.dst_port) return dst_port < other.dst_port;
            return protocol < other.protocol;
        }
    };
    
    // Data for each connection
    struct ConnectionData {
        std::chrono::steady_clock::time_point last_seen;
        uint64_t packets;
        uint64_t bytes;
        std::string state;
    };
    
    // Normalize connection key (always use the lower IP/port as source)
    void normalizeKey(ConnectionKey& key) {
        if (key.src_ip > key.dst_ip || 
            (key.src_ip == key.dst_ip && key.src_port > key.dst_port)) {
            std::swap(key.src_ip, key.dst_ip);
            std::swap(key.src_port, key.dst_port);
        }
    }
    
    // Display loop for showing connections
    void displayLoop() {
        while (running_) {
            // Sleep for a bit
            std::this_thread::sleep_for(std::chrono::seconds(1));
            
            // Clean up expired connections (30 seconds timeout)
            cleanupExpiredConnections(30000);
            
            // Get current connections
            auto connections = getConnections();
            
            // Clear screen
            std::cout << "\033[2J\033[1;1H";
            
            // Print header
            std::cout << "======== Connection Monitor ========" << std::endl;
            std::cout << "Total connections: " << connections.size() << std::endl;
            std::cout << std::endl;
            
            // Print table header
            std::cout << std::left
                     << std::setw(15) << "Source"
                     << std::setw(15) << "Destination"
                     << std::setw(8) << "Protocol"
                     << std::setw(12) << "State"
                     << std::setw(10) << "Packets"
                     << std::setw(10) << "Bytes"
                     << "Last Seen" << std::endl;
            std::cout << std::string(80, '-') << std::endl;
            
            // Sort connections by protocol, then by source IP
            std::map<std::string, std::vector<std::pair<ConnectionKey, ConnectionData>>> sorted_connections;
            for (const auto& conn : connections) {
                std::string protocol = getProtocolName(conn.first.protocol);
                sorted_connections[protocol].push_back(conn);
            }
            
            // Print each connection
            auto now = std::chrono::steady_clock::now();
            for (const auto& protocol_group : sorted_connections) {
                for (const auto& conn : protocol_group.second) {
                    const auto& key = conn.first;
                    const auto& data = conn.second;
                    
                    std::string source = ipToString(key.src_ip) + ":" + std::to_string(key.src_port);
                    std::string dest = ipToString(key.dst_ip) + ":" + std::to_string(key.dst_port);
                    
                    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                        now - data.last_seen).count();
                    
                    std::string last_seen = std::to_string(elapsed) + "s ago";
                    
                    std::cout << std::left
                             << std::setw(15) << source
                             << std::setw(15) << dest
                             << std::setw(8) << protocol_group.first
                             << std::setw(12) << data.state
                             << std::setw(10) << data.packets
                             << std::setw(10) << data.bytes
                             << last_seen << std::endl;
                }
            }
            
            std::cout << std::endl;
            std::cout << "Press Ctrl+C to exit" << std::endl;
        }
    }
    
    std::map<ConnectionKey, ConnectionData> connections_;
    mutable std::mutex mutex_;
    std::thread display_thread_;
    std::atomic<bool> running_;
};

// Print usage
void printUsage(const char* program_name) {
    std::cout << "Usage: " << program_name << " <interface> [filter]" << std::endl;
    std::cout << "Example: " << program_name << " en0 \"tcp or udp\"" << std::endl;
    
    // Print available interfaces
    std::cout << "\nAvailable interfaces:" << std::endl;
    auto interfaces = packet_processor::PacketCapture::getDeviceNames();
    for (const auto& iface : interfaces) {
        std::cout << "  - " << iface << std::endl;
    }
}

// Main entry point
int main(int argc, char* argv[]) {
    // Register signal handlers
    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);
    
    // Check arguments
    if (argc < 2) {
        printUsage(argv[0]);
        return 1;
    }
    
    // Get interface name
    std::string interface = argv[1];
    
    // Get optional filter
    std::string filter = (argc > 2) ? argv[2] : "tcp or udp";
    
    // Configure packet processor
    packet_processor::PacketProcessorConfig config;
    config.device_name = interface;
    config.bpf_filter = filter;
    config.promiscuous_mode = true;
    config.enable_stats = false;  // Disable stats for cleaner display
    config.log_level = "error";   // Reduce log output
    
    // Create packet processor
    packet_processor::PacketProcessor processor(config);
    
    // Create connection monitor handler
    auto handler = std::make_shared<ConnectionMonitorHandler>();
    processor.addHandler(handler);
    
    // Initialize processor
    std::cout << "Initializing connection monitor on " << interface << "..." << std::endl;
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
    
    // Main loop
    while (running) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    // Stop processor
    processor.stop();
    
    std::cout << "Connection monitor stopped" << std::endl;
    return 0;
} 