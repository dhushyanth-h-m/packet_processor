#include "packet_processor/protocol/connection_tracker.h"
#include <algorithm>
#include <chrono>
#include <iostream>
#include <functional>

namespace packet_processor {

// Connection tuple equality operator
bool ConnectionTuple::operator==(const ConnectionTuple& other) const {
    return (src_ip == other.src_ip &&
            dst_ip == other.dst_ip &&
            src_port == other.src_port &&
            dst_port == other.dst_port &&
            protocol == other.protocol);
}

// Hash function for ConnectionTuple
std::size_t ConnectionTupleHash::operator()(const ConnectionTuple& tuple) const {
    // Use a simple hash combining technique
    std::size_t hash = tuple.src_ip;
    hash = hash * 31 + tuple.dst_ip;
    hash = hash * 31 + tuple.src_port;
    hash = hash * 31 + tuple.dst_port;
    hash = hash * 31 + tuple.protocol;
    return hash;
}

// Constructor
ConnectionTracker::ConnectionTracker(size_t max_connections, uint64_t timeout_ms)
    : max_connections_(max_connections),
      timeout_ms_(timeout_ms),
      last_cleanup_(std::chrono::steady_clock::now()) {
}

// Update a connection based on a packet
Connection* ConnectionTracker::updateConnection(const Packet& packet) {
    // Create a bidirectional tuple for the packet
    ConnectionTuple tuple = createBidirectionalTuple(packet);
    
    // Lock the mutex for thread safety
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Try to find an existing connection
    auto it = connections_.find(tuple);
    if (it == connections_.end()) {
        // Check if we've reached the maximum number of connections
        if (max_connections_ > 0 && connections_.size() >= max_connections_) {
            // Clean up expired connections
            cleanupExpiredConnections(true);
            
            // Check again if we're still at the limit
            if (connections_.size() >= max_connections_) {
                return nullptr;  // Cannot add more connections
            }
        }
        
        // Create a new connection
        Connection conn;
        conn.tuple = tuple;
        conn.state = ConnectionState::NEW;
        conn.last_seen = std::chrono::steady_clock::now();
        conn.bytes_sent = 0;
        conn.bytes_received = 0;
        conn.packets_sent = 0;
        conn.packets_received = 0;
        conn.last_seq = 0;
        conn.last_ack = 0;
        
        // Add the connection to the map
        auto result = connections_.emplace(tuple, conn);
        it = result.first;
    }
    
    // Update the connection
    Connection& conn = it->second;
    
    // Update timestamp
    conn.last_seen = std::chrono::steady_clock::now();
    
    // Update bytes and packets
    if (packet.ip_src == tuple.src_ip && packet.port_src == tuple.src_port) {
        // Packet from source to destination
        conn.bytes_sent += packet.length;
        conn.packets_sent++;
        conn.last_seq = packet.tcp_seq;
    } else {
        // Packet from destination to source
        conn.bytes_received += packet.length;
        conn.packets_received++;
        conn.last_ack = packet.tcp_ack;
    }
    
    // Update TCP state if it's a TCP packet
    if (packet.ip_protocol == IPPROTO_TCP) {
        updateTcpState(conn, packet);
    }
    
    // Check if we need to clean up expired connections
    auto now = std::chrono::steady_clock::now();
    if (std::chrono::duration_cast<std::chrono::milliseconds>(now - last_cleanup_).count() >= timeout_ms_) {
        cleanupExpiredConnections(false);
    }
    
    return &it->second;
}

// Get a connection by tuple
Connection* ConnectionTracker::getConnection(const ConnectionTuple& tuple) {
    // Lock the mutex for thread safety
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Try to find the connection
    auto it = connections_.find(tuple);
    if (it != connections_.end()) {
        return &it->second;
    }
    
    return nullptr;
}

// Remove a connection
bool ConnectionTracker::removeConnection(const ConnectionTuple& tuple) {
    // Lock the mutex for thread safety
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Try to find and remove the connection
    return connections_.erase(tuple) > 0;
}

// Clean up expired connections
size_t ConnectionTracker::cleanupExpiredConnections(bool force) {
    // Current time
    auto now = std::chrono::steady_clock::now();
    
    // Check if we need to clean up
    if (!force && std::chrono::duration_cast<std::chrono::milliseconds>(now - last_cleanup_).count() < timeout_ms_) {
        return 0;  // Not time to clean up yet
    }
    
    // Update last cleanup time
    last_cleanup_ = now;
    
    // Lock the mutex for thread safety
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Find and remove expired connections
    size_t removed = 0;
    auto it = connections_.begin();
    while (it != connections_.end()) {
        const Connection& conn = it->second;
        
        // Check if the connection has expired
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - conn.last_seen).count();
        if (elapsed >= timeout_ms_) {
            // Connection has expired, remove it
            it = connections_.erase(it);
            removed++;
        } else {
            // Connection is still active
            ++it;
        }
    }
    
    return removed;
}

// Get all active connections
std::vector<Connection> ConnectionTracker::getConnections() const {
    // Lock the mutex for thread safety
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Copy all connections to a vector
    std::vector<Connection> result;
    result.reserve(connections_.size());
    
    for (const auto& pair : connections_) {
        result.push_back(pair.second);
    }
    
    return result;
}

// Get the number of active connections
size_t ConnectionTracker::getConnectionCount() const {
    // Lock the mutex for thread safety
    std::lock_guard<std::mutex> lock(mutex_);
    
    return connections_.size();
}

// Reset the connection tracker
void ConnectionTracker::reset() {
    // Lock the mutex for thread safety
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Clear all connections
    connections_.clear();
    
    // Reset last cleanup time
    last_cleanup_ = std::chrono::steady_clock::now();
}

// Create a bidirectional connection tuple
ConnectionTuple ConnectionTracker::createBidirectionalTuple(const Packet& packet) const {
    ConnectionTuple tuple;
    
    // Ensure that the tuple is the same regardless of direction
    // by using the lower IP/port as the source
    if (packet.ip_src < packet.ip_dst ||
        (packet.ip_src == packet.ip_dst && packet.port_src < packet.port_dst)) {
        tuple.src_ip = packet.ip_src;
        tuple.dst_ip = packet.ip_dst;
        tuple.src_port = packet.port_src;
        tuple.dst_port = packet.port_dst;
    } else {
        tuple.src_ip = packet.ip_dst;
        tuple.dst_ip = packet.ip_src;
        tuple.src_port = packet.port_dst;
        tuple.dst_port = packet.port_src;
    }
    
    tuple.protocol = packet.ip_protocol;
    
    return tuple;
}

// Update TCP connection state
void ConnectionTracker::updateTcpState(Connection& connection, const Packet& packet) {
    // Extract TCP flags
    uint8_t flags = packet.tcp_flags;
    bool is_syn = (flags & TCPFlags::SYN) != 0;
    bool is_ack = (flags & TCPFlags::ACK) != 0;
    bool is_fin = (flags & TCPFlags::FIN) != 0;
    bool is_rst = (flags & TCPFlags::RST) != 0;
    
    // Check if packet is from source to destination
    bool from_src = (packet.ip_src == connection.tuple.src_ip && 
                     packet.port_src == connection.tuple.src_port);
    
    // Update connection state based on TCP flags and current state
    switch (connection.state) {
        case ConnectionState::NEW:
            if (is_syn && !is_ack) {
                // SYN packet, transition to SYN_SENT
                connection.state = ConnectionState::SYN_SENT;
            }
            break;
        
        case ConnectionState::SYN_SENT:
            if (is_syn && is_ack) {
                // SYN-ACK packet, transition to SYN_RECEIVED
                connection.state = ConnectionState::SYN_RECEIVED;
            }
            break;
        
        case ConnectionState::SYN_RECEIVED:
            if (is_ack && !is_syn && !is_fin && !is_rst) {
                // ACK packet, connection established
                connection.state = ConnectionState::ESTABLISHED;
            }
            break;
        
        case ConnectionState::ESTABLISHED:
            if (is_fin) {
                // FIN packet, transition to FIN_WAIT_1 or CLOSE_WAIT
                connection.state = from_src ? ConnectionState::FIN_WAIT_1 : ConnectionState::CLOSE_WAIT;
            } else if (is_rst) {
                // RST packet, connection closed
                connection.state = ConnectionState::CLOSED;
            }
            break;
        
        case ConnectionState::FIN_WAIT_1:
            if (is_fin && is_ack) {
                // FIN-ACK packet, transition to CLOSING
                connection.state = ConnectionState::CLOSING;
            } else if (is_ack && !is_fin) {
                // ACK packet, transition to FIN_WAIT_2
                connection.state = ConnectionState::FIN_WAIT_2;
            }
            break;
        
        case ConnectionState::FIN_WAIT_2:
            if (is_fin) {
                // FIN packet, transition to TIME_WAIT
                connection.state = ConnectionState::TIME_WAIT;
            }
            break;
        
        case ConnectionState::CLOSE_WAIT:
            if (is_fin) {
                // FIN packet, transition to LAST_ACK
                connection.state = ConnectionState::LAST_ACK;
            }
            break;
        
        case ConnectionState::CLOSING:
            if (is_ack && !is_fin && !is_rst) {
                // ACK packet, transition to TIME_WAIT
                connection.state = ConnectionState::TIME_WAIT;
            }
            break;
        
        case ConnectionState::LAST_ACK:
            if (is_ack && !is_fin && !is_rst) {
                // ACK packet, connection closed
                connection.state = ConnectionState::CLOSED;
            }
            break;
        
        case ConnectionState::TIME_WAIT:
            // Waiting for timeout
            break;
        
        case ConnectionState::CLOSED:
            // Connection already closed
            break;
    }
    
    // Always transition to CLOSED on RST
    if (is_rst) {
        connection.state = ConnectionState::CLOSED;
    }
}

} // namespace packet_processor 