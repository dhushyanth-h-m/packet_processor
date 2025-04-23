#pragma once

#include "packet_processor/core/packet.h"
#include <cstdint>
#include <unordered_map>
#include <memory>
#include <functional>
#include <string>

namespace packet_processor {

/**
 * Ethernet protocol types
 */
enum class EtherType : uint16_t {
    IPv4 = 0x0800,
    ARP = 0x0806,
    IPv6 = 0x86DD,
    VLAN = 0x8100,
    UNKNOWN = 0xFFFF
};

/**
 * IP protocol types
 */
enum class IPProtocol : uint8_t {
    ICMP = 1,
    TCP = 6,
    UDP = 17,
    UNKNOWN = 255
};

/**
 * TCP flags
 */
enum class TCPFlags : uint8_t {
    FIN = 0x01,
    SYN = 0x02,
    RST = 0x04,
    PSH = 0x08,
    ACK = 0x10,
    URG = 0x20,
    ECE = 0x40,
    CWR = 0x80
};

/**
 * Class for parsing network protocols
 */
class ProtocolParser {
public:
    /**
     * Constructor
     */
    ProtocolParser();
    
    /**
     * Parse a packet
     * 
     * @param packet Packet to parse
     * @return True if parsing was successful, false otherwise
     */
    bool parsePacket(Packet& packet);
    
    /**
     * Parse Ethernet header
     * 
     * @param packet Packet to parse
     * @param offset Offset to start parsing from
     * @return Offset after parsing or 0 if parsing failed
     */
    uint32_t parseEthernet(Packet& packet, uint32_t offset);
    
    /**
     * Parse IPv4 header
     * 
     * @param packet Packet to parse
     * @param offset Offset to start parsing from
     * @return Offset after parsing or 0 if parsing failed
     */
    uint32_t parseIPv4(Packet& packet, uint32_t offset);
    
    /**
     * Parse IPv6 header
     * 
     * @param packet Packet to parse
     * @param offset Offset to start parsing from
     * @return Offset after parsing or 0 if parsing failed
     */
    uint32_t parseIPv6(Packet& packet, uint32_t offset);
    
    /**
     * Parse TCP header
     * 
     * @param packet Packet to parse
     * @param offset Offset to start parsing from
     * @return Offset after parsing or 0 if parsing failed
     */
    uint32_t parseTCP(Packet& packet, uint32_t offset);
    
    /**
     * Parse UDP header
     * 
     * @param packet Packet to parse
     * @param offset Offset to start parsing from
     * @return Offset after parsing or 0 if parsing failed
     */
    uint32_t parseUDP(Packet& packet, uint32_t offset);
    
    /**
     * Get IP address string from uint32_t
     * 
     * @param ip IP address as uint32_t
     * @return IP address as string
     */
    static std::string ipToString(uint32_t ip);
};

} // namespace packet_processor 