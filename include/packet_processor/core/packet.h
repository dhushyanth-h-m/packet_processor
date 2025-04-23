#pragma once

#include <cstdint>

namespace packet_processor {

/**
 * Structure representing a captured network packet with metadata
 */
struct Packet {
    // Raw packet data
    const uint8_t* data;
    
    // Length of the packet in bytes
    uint32_t length;
    
    // Timestamp in microseconds
    uint64_t timestamp;
    
    // Buffer ID that contains this packet
    uint32_t buffer_id;
    
    // Ethernet type
    uint16_t eth_type;
    
    // IP version (4 or 6)
    uint8_t ip_version;
    
    // IP protocol (TCP, UDP, etc.)
    uint8_t ip_protocol;
    
    // Source IP address (stored as uint32_t for IPv4)
    uint32_t ip_src;
    
    // Destination IP address (stored as uint32_t for IPv4)
    uint32_t ip_dst;
    
    // Source port
    uint16_t port_src;
    
    // Destination port
    uint16_t port_dst;
    
    // TCP sequence number
    uint32_t tcp_seq;
    
    // TCP acknowledgment number
    uint32_t tcp_ack;
    
    // TCP flags
    uint8_t tcp_flags;
};

} // namespace packet_processor 