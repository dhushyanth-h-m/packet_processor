#include "packet_processor/parser/protocol_parser.h"
#include <arpa/inet.h>
#include <cstring>
#include <sstream>
#include <iomanip>

namespace packet_processor {

ProtocolParser::ProtocolParser() {
}

bool ProtocolParser::parsePacket(Packet& packet) {
    // Start parsing from the beginning of the packet
    uint32_t offset = 0;
    
    // Parse Ethernet header
    offset = parseEthernet(packet, offset);
    if (offset == 0) {
        return false;
    }
    
    // Parse IP header based on EtherType
    if (packet.eth_type == static_cast<uint16_t>(EtherType::IPv4)) {
        offset = parseIPv4(packet, offset);
        if (offset == 0) {
            return false;
        }
    } else if (packet.eth_type == static_cast<uint16_t>(EtherType::IPv6)) {
        offset = parseIPv6(packet, offset);
        if (offset == 0) {
            return false;
        }
    } else {
        // Unsupported or non-IP protocol
        return true;
    }
    
    // Parse transport layer based on IP protocol
    if (packet.ip_protocol == static_cast<uint8_t>(IPProtocol::TCP)) {
        offset = parseTCP(packet, offset);
        if (offset == 0) {
            return false;
        }
    } else if (packet.ip_protocol == static_cast<uint8_t>(IPProtocol::UDP)) {
        offset = parseUDP(packet, offset);
        if (offset == 0) {
            return false;
        }
    }
    
    return true;
}

uint32_t ProtocolParser::parseEthernet(Packet& packet, uint32_t offset) {
    // Check if packet has enough data for Ethernet header (14 bytes)
    if (packet.length < offset + 14) {
        return 0;
    }
    
    // Get EtherType (bytes 12-13)
    packet.eth_type = ntohs(*reinterpret_cast<const uint16_t*>(packet.data + offset + 12));
    
    // Return offset after Ethernet header
    return offset + 14;
}

uint32_t ProtocolParser::parseIPv4(Packet& packet, uint32_t offset) {
    // Check if packet has enough data for IPv4 header (at least 20 bytes)
    if (packet.length < offset + 20) {
        return 0;
    }
    
    // Get pointer to IPv4 header
    const uint8_t* ip_header = packet.data + offset;
    
    // Get header length (in 32-bit words)
    uint8_t ihl = (ip_header[0] & 0x0F);
    if (ihl < 5) {
        // Invalid header length
        return 0;
    }
    
    // Calculate header length in bytes
    uint32_t ip_header_length = ihl * 4;
    
    // Check if packet has enough data for the full IPv4 header
    if (packet.length < offset + ip_header_length) {
        return 0;
    }
    
    // Set IP version
    packet.ip_version = 4;
    
    // Get protocol
    packet.ip_protocol = ip_header[9];
    
    // Get source and destination IP addresses
    packet.ip_src = ntohl(*reinterpret_cast<const uint32_t*>(ip_header + 12));
    packet.ip_dst = ntohl(*reinterpret_cast<const uint32_t*>(ip_header + 16));
    
    // Return offset after IPv4 header
    return offset + ip_header_length;
}

uint32_t ProtocolParser::parseIPv6(Packet& packet, uint32_t offset) {
    // Check if packet has enough data for IPv6 header (40 bytes)
    if (packet.length < offset + 40) {
        return 0;
    }
    
    // Get pointer to IPv6 header
    const uint8_t* ip_header = packet.data + offset;
    
    // Set IP version
    packet.ip_version = 6;
    
    // Get next header (protocol)
    packet.ip_protocol = ip_header[6];
    
    // IPv6 addresses would need special handling
    // For now, we'll just store the lower 32 bits as a simple example
    packet.ip_src = ntohl(*reinterpret_cast<const uint32_t*>(ip_header + 8));
    packet.ip_dst = ntohl(*reinterpret_cast<const uint32_t*>(ip_header + 24));
    
    // Return offset after IPv6 header
    return offset + 40;
}

uint32_t ProtocolParser::parseTCP(Packet& packet, uint32_t offset) {
    // Check if packet has enough data for TCP header (at least 20 bytes)
    if (packet.length < offset + 20) {
        return 0;
    }
    
    // Get pointer to TCP header
    const uint8_t* tcp_header = packet.data + offset;
    
    // Get source and destination ports
    packet.port_src = ntohs(*reinterpret_cast<const uint16_t*>(tcp_header));
    packet.port_dst = ntohs(*reinterpret_cast<const uint16_t*>(tcp_header + 2));
    
    // Get sequence and acknowledgment numbers
    packet.tcp_seq = ntohl(*reinterpret_cast<const uint32_t*>(tcp_header + 4));
    packet.tcp_ack = ntohl(*reinterpret_cast<const uint32_t*>(tcp_header + 8));
    
    // Get header length (in 32-bit words)
    uint8_t data_offset = (tcp_header[12] >> 4);
    if (data_offset < 5) {
        // Invalid header length
        return 0;
    }
    
    // Calculate header length in bytes
    uint32_t tcp_header_length = data_offset * 4;
    
    // Check if packet has enough data for the full TCP header
    if (packet.length < offset + tcp_header_length) {
        return 0;
    }
    
    // Get flags
    packet.tcp_flags = tcp_header[13];
    
    // Return offset after TCP header
    return offset + tcp_header_length;
}

uint32_t ProtocolParser::parseUDP(Packet& packet, uint32_t offset) {
    // Check if packet has enough data for UDP header (8 bytes)
    if (packet.length < offset + 8) {
        return 0;
    }
    
    // Get pointer to UDP header
    const uint8_t* udp_header = packet.data + offset;
    
    // Get source and destination ports
    packet.port_src = ntohs(*reinterpret_cast<const uint16_t*>(udp_header));
    packet.port_dst = ntohs(*reinterpret_cast<const uint16_t*>(udp_header + 2));
    
    // Return offset after UDP header
    return offset + 8;
}

std::string ProtocolParser::ipToString(uint32_t ip) {
    std::ostringstream oss;
    
    // Convert to network byte order for byte-by-byte access
    uint32_t network_ip = htonl(ip);
    const uint8_t* bytes = reinterpret_cast<const uint8_t*>(&network_ip);
    
    // Format as a.b.c.d
    oss << static_cast<int>(bytes[0]) << "."
        << static_cast<int>(bytes[1]) << "."
        << static_cast<int>(bytes[2]) << "."
        << static_cast<int>(bytes[3]);
    
    return oss.str();
}

} // namespace packet_processor 