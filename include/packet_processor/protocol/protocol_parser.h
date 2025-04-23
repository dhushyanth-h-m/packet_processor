#pragma once

#include <cstdint>
#include <unordered_map>
#include <memory>
#include <vector>
#include <functional>
#include <string>
#include "../packet_processor.h"

namespace packet_processor {

/**
 * @brief Protocol types for packet classification
 */
enum class ProtocolType {
    UNKNOWN,
    ETHERNET,
    ARP,
    IPv4,
    IPv6,
    ICMP,
    ICMPv6,
    TCP,
    UDP,
    HTTP,
    DNS,
    TLS
};

/**
 * @brief Protocol parser interface for packet protocols
 */
class IProtocolParser {
public:
    virtual ~IProtocolParser() = default;
    
    /**
     * @brief Parse a packet and fill in protocol-specific metadata
     * 
     * @param packet Packet to parse
     * @param offset Offset to start parsing from
     * @return Next offset to continue parsing from, or 0 if parsing should stop
     */
    virtual uint32_t parse(Packet& packet, uint32_t offset) = 0;
    
    /**
     * @brief Get the protocol type
     * 
     * @return Protocol type
     */
    virtual ProtocolType getType() const = 0;
    
    /**
     * @brief Get human-readable protocol name
     * 
     * @return Protocol name
     */
    virtual std::string getName() const = 0;
};

/**
 * @brief Ethernet protocol parser
 */
class EthernetParser : public IProtocolParser {
public:
    uint32_t parse(Packet& packet, uint32_t offset) override;
    ProtocolType getType() const override { return ProtocolType::ETHERNET; }
    std::string getName() const override { return "Ethernet"; }
};

/**
 * @brief IPv4 protocol parser
 */
class IPv4Parser : public IProtocolParser {
public:
    uint32_t parse(Packet& packet, uint32_t offset) override;
    ProtocolType getType() const override { return ProtocolType::IPv4; }
    std::string getName() const override { return "IPv4"; }
};

/**
 * @brief IPv6 protocol parser
 */
class IPv6Parser : public IProtocolParser {
public:
    uint32_t parse(Packet& packet, uint32_t offset) override;
    ProtocolType getType() const override { return ProtocolType::IPv6; }
    std::string getName() const override { return "IPv6"; }
};

/**
 * @brief TCP protocol parser
 */
class TCPParser : public IProtocolParser {
public:
    uint32_t parse(Packet& packet, uint32_t offset) override;
    ProtocolType getType() const override { return ProtocolType::TCP; }
    std::string getName() const override { return "TCP"; }
};

/**
 * @brief UDP protocol parser
 */
class UDPParser : public IProtocolParser {
public:
    uint32_t parse(Packet& packet, uint32_t offset) override;
    ProtocolType getType() const override { return ProtocolType::UDP; }
    std::string getName() const override { return "UDP"; }
};

/**
 * @brief Main protocol parser class that orchestrates protocol-specific parsers
 */
class ProtocolParser {
public:
    /**
     * @brief Construct a new Protocol Parser
     */
    ProtocolParser();
    
    /**
     * @brief Parse a packet
     * 
     * @param packet Packet to parse
     * @return Vector of detected protocol types
     */
    std::vector<ProtocolType> parsePacket(Packet& packet);
    
    /**
     * @brief Register a protocol handler
     * 
     * @param protocol Protocol type
     * @param handler Function to call when a packet of this protocol is parsed
     */
    void registerProtocolHandler(ProtocolType protocol, 
                                std::function<void(const Packet&)> handler);
    
    /**
     * @brief Get statistics for a specific protocol
     * 
     * @param protocol Protocol type
     * @return Pair of (packet count, byte count)
     */
    std::pair<uint64_t, uint64_t> getProtocolStats(ProtocolType protocol) const;
    
    /**
     * @brief Reset all statistics
     */
    void resetStats();
    
private:
    // Protocol parsers
    std::unordered_map<ProtocolType, std::unique_ptr<IProtocolParser>> parsers_;
    
    // Protocol handlers
    std::unordered_map<ProtocolType, std::function<void(const Packet&)>> handlers_;
    
    // Protocol statistics (packets, bytes)
    std::unordered_map<ProtocolType, std::pair<uint64_t, uint64_t>> stats_;
    
    // Protocol parsing chain
    std::unordered_map<uint16_t, ProtocolType> eth_types_;
    std::unordered_map<uint8_t, ProtocolType> ip_protocols_;
    
    /**
     * @brief Register all protocol parsers
     */
    void registerParsers();
    
    /**
     * @brief Update statistics for a protocol
     * 
     * @param protocol Protocol type
     * @param bytes Number of bytes
     */
    void updateStats(ProtocolType protocol, uint32_t bytes);
};

} // namespace packet_processor 