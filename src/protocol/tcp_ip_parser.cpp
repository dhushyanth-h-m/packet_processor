#include "packet_processor/protocol/protocol_parser.h"
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/in.h>

namespace packet_processor {

// Ethernet header parser
uint32_t EthernetParser::parse(Packet& packet, uint32_t offset) {
    // Ensure we have enough data for an Ethernet header
    if (packet.length < offset + sizeof(struct ether_header)) {
        return 0;  // Not enough data
    }
    
    // Cast the packet data to an Ethernet header
    const struct ether_header* eth = 
        reinterpret_cast<const struct ether_header*>(packet.data + offset);
    
    // Extract Ethernet type
    packet.eth_type = ntohs(eth->ether_type);
    
    // Return the offset to the next header
    return offset + sizeof(struct ether_header);
}

// IPv4 header parser
uint32_t IPv4Parser::parse(Packet& packet, uint32_t offset) {
    // Ensure we have enough data for an IPv4 header
    if (packet.length < offset + sizeof(struct ip)) {
        return 0;  // Not enough data
    }
    
    // Cast the packet data to an IPv4 header
    const struct ip* ip_header = 
        reinterpret_cast<const struct ip*>(packet.data + offset);
    
    // Check for IPv4
    if (ip_header->ip_v != 4) {
        return 0;  // Not IPv4
    }
    
    // Extract IP version
    packet.ip_version = ip_header->ip_v;
    
    // Extract IP protocol
    packet.ip_protocol = ip_header->ip_p;
    
    // Extract source and destination IP addresses
    packet.ip_src = ntohl(ip_header->ip_src.s_addr);
    packet.ip_dst = ntohl(ip_header->ip_dst.s_addr);
    
    // Calculate header length (in bytes)
    uint32_t ip_header_length = ip_header->ip_hl * 4;
    
    // Return the offset to the next header
    return offset + ip_header_length;
}

// IPv6 header parser
uint32_t IPv6Parser::parse(Packet& packet, uint32_t offset) {
    // Ensure we have enough data for an IPv6 header
    if (packet.length < offset + sizeof(struct ip6_hdr)) {
        return 0;  // Not enough data
    }
    
    // Cast the packet data to an IPv6 header
    const struct ip6_hdr* ip6_header = 
        reinterpret_cast<const struct ip6_hdr*>(packet.data + offset);
    
    // Check for IPv6
    if ((ip6_header->ip6_vfc >> 4) != 6) {
        return 0;  // Not IPv6
    }
    
    // Extract IP version
    packet.ip_version = 6;
    
    // Extract IP protocol (next header)
    packet.ip_protocol = ip6_header->ip6_nxt;
    
    // IPv6 addresses are not stored in the packet metadata
    // We could add specific fields for IPv6 addresses if needed
    
    // Return the offset to the next header
    return offset + sizeof(struct ip6_hdr);
}

// TCP header parser
uint32_t TCPParser::parse(Packet& packet, uint32_t offset) {
    // Ensure we have enough data for a TCP header
    if (packet.length < offset + sizeof(struct tcphdr)) {
        return 0;  // Not enough data
    }
    
    // Cast the packet data to a TCP header
    const struct tcphdr* tcp_header = 
        reinterpret_cast<const struct tcphdr*>(packet.data + offset);
    
    // Extract source and destination ports
    packet.port_src = ntohs(tcp_header->th_sport);
    packet.port_dst = ntohs(tcp_header->th_dport);
    
    // Extract sequence and acknowledgment numbers
    packet.tcp_seq = ntohl(tcp_header->th_seq);
    packet.tcp_ack = ntohl(tcp_header->th_ack);
    
    // Extract TCP flags
    packet.tcp_flags = tcp_header->th_flags;
    
    // Calculate header length (in bytes)
    uint32_t tcp_header_length = tcp_header->th_off * 4;
    
    // Return the offset to the next header (payload)
    return offset + tcp_header_length;
}

// UDP header parser
uint32_t UDPParser::parse(Packet& packet, uint32_t offset) {
    // Ensure we have enough data for a UDP header
    if (packet.length < offset + sizeof(struct udphdr)) {
        return 0;  // Not enough data
    }
    
    // Cast the packet data to a UDP header
    const struct udphdr* udp_header = 
        reinterpret_cast<const struct udphdr*>(packet.data + offset);
    
    // Extract source and destination ports
    packet.port_src = ntohs(udp_header->uh_sport);
    packet.port_dst = ntohs(udp_header->uh_dport);
    
    // Return the offset to the next header (payload)
    return offset + sizeof(struct udphdr);
}

// Main protocol parser
ProtocolParser::ProtocolParser() {
    registerParsers();
}

// Register all protocol parsers
void ProtocolParser::registerParsers() {
    // Register ethernet parser
    parsers_[ProtocolType::ETHERNET] = std::make_unique<EthernetParser>();
    
    // Register IP parsers
    parsers_[ProtocolType::IPv4] = std::make_unique<IPv4Parser>();
    parsers_[ProtocolType::IPv6] = std::make_unique<IPv6Parser>();
    
    // Register transport layer parsers
    parsers_[ProtocolType::TCP] = std::make_unique<TCPParser>();
    parsers_[ProtocolType::UDP] = std::make_unique<UDPParser>();
    
    // Register Ethernet type to protocol mappings
    eth_types_[ETHERTYPE_IP] = ProtocolType::IPv4;
    eth_types_[ETHERTYPE_IPV6] = ProtocolType::IPv6;
    eth_types_[ETHERTYPE_ARP] = ProtocolType::ARP;
    
    // Register IP protocol to protocol mappings
    ip_protocols_[IPPROTO_TCP] = ProtocolType::TCP;
    ip_protocols_[IPPROTO_UDP] = ProtocolType::UDP;
    ip_protocols_[IPPROTO_ICMP] = ProtocolType::ICMP;
    ip_protocols_[IPPROTO_ICMPV6] = ProtocolType::ICMPv6;
    
    // Initialize statistics
    resetStats();
}

// Parse a packet
std::vector<ProtocolType> ProtocolParser::parsePacket(Packet& packet) {
    std::vector<ProtocolType> detected_protocols;
    uint32_t offset = 0;
    
    // Start with Ethernet
    auto ethernet_parser = parsers_[ProtocolType::ETHERNET].get();
    if (ethernet_parser) {
        offset = ethernet_parser->parse(packet, offset);
        if (offset == 0) {
            return detected_protocols;  // Failed to parse Ethernet header
        }
        
        detected_protocols.push_back(ProtocolType::ETHERNET);
        updateStats(ProtocolType::ETHERNET, sizeof(struct ether_header));
        
        // Handle Ethernet type
        auto eth_type_it = eth_types_.find(packet.eth_type);
        if (eth_type_it != eth_types_.end()) {
            ProtocolType next_protocol = eth_type_it->second;
            
            // Parse IP
            auto ip_parser = parsers_[next_protocol].get();
            if (ip_parser) {
                uint32_t next_offset = ip_parser->parse(packet, offset);
                if (next_offset > offset) {
                    offset = next_offset;
                    detected_protocols.push_back(next_protocol);
                    updateStats(next_protocol, next_offset - offset);
                    
                    // Handle IP protocol
                    auto ip_protocol_it = ip_protocols_.find(packet.ip_protocol);
                    if (ip_protocol_it != ip_protocols_.end()) {
                        ProtocolType transport_protocol = ip_protocol_it->second;
                        
                        // Parse transport layer
                        auto transport_parser = parsers_[transport_protocol].get();
                        if (transport_parser) {
                            uint32_t transport_offset = transport_parser->parse(packet, offset);
                            if (transport_offset > offset) {
                                offset = transport_offset;
                                detected_protocols.push_back(transport_protocol);
                                updateStats(transport_protocol, transport_offset - offset);
                                
                                // Call any registered protocol handlers
                                auto handler_it = handlers_.find(transport_protocol);
                                if (handler_it != handlers_.end()) {
                                    handler_it->second(packet);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    return detected_protocols;
}

// Register a protocol handler
void ProtocolParser::registerProtocolHandler(ProtocolType protocol, 
                                          std::function<void(const Packet&)> handler) {
    handlers_[protocol] = handler;
}

// Get statistics for a specific protocol
std::pair<uint64_t, uint64_t> ProtocolParser::getProtocolStats(ProtocolType protocol) const {
    auto it = stats_.find(protocol);
    if (it != stats_.end()) {
        return it->second;
    }
    return {0, 0};
}

// Reset all statistics
void ProtocolParser::resetStats() {
    stats_.clear();
    
    // Initialize stats for all protocol types
    for (int i = static_cast<int>(ProtocolType::UNKNOWN); 
         i <= static_cast<int>(ProtocolType::TLS); ++i) {
        ProtocolType type = static_cast<ProtocolType>(i);
        stats_[type] = {0, 0};
    }
}

// Update statistics for a protocol
void ProtocolParser::updateStats(ProtocolType protocol, uint32_t bytes) {
    auto it = stats_.find(protocol);
    if (it != stats_.end()) {
        // Update packet count and byte count
        it->second.first++;
        it->second.second += bytes;
    }
}

} // namespace packet_processor 