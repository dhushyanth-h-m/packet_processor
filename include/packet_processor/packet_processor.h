#pragma once

#include <memory>
#include <string>
#include <vector>
#include <functional>

namespace packet_processor {

/**
 * @brief Main configuration for the packet processor engine
 */
struct PacketProcessorConfig {
    std::string device_name;                  ///< Network interface name (e.g., "en0")
    int capture_buffer_size = 2 * 1024 * 1024; ///< libpcap buffer size in bytes (default 2MB)
    int zero_copy_buffer_size = 4 * 1024 * 1024; ///< Zero-copy buffer size in bytes (default 4MB)
    int ring_buffer_count = 8;                ///< Number of ring buffers to use
    int processing_threads = 0;               ///< Number of processing threads (0 = auto-detect)
    std::string bpf_filter;                   ///< BPF filter string (e.g., "tcp port 80")
    bool promiscuous_mode = false;            ///< Enable promiscuous mode
    int snaplen = 65535;                      ///< Packet capture length
    bool enable_stats = true;                 ///< Enable performance statistics
    int stats_interval_ms = 1000;             ///< Statistics collection interval in milliseconds
    std::string log_level = "info";           ///< Logging level (debug, info, warning, error)
};

/**
 * @brief Packet data structure with metadata
 */
struct Packet {
    const uint8_t* data;        ///< Pointer to packet data (zero-copy)
    uint32_t length;            ///< Length of packet data
    uint64_t timestamp;         ///< Capture timestamp (microseconds)
    uint32_t buffer_id;         ///< ID of the buffer containing this packet
    
    // Layer 2 metadata (set by parsers)
    uint16_t eth_type;          ///< Ethernet type
    
    // Layer 3 metadata
    uint8_t ip_version;         ///< IP version (4 or 6)
    uint8_t ip_protocol;        ///< IP protocol number
    uint32_t ip_src;            ///< Source IP address (IPv4 only)
    uint32_t ip_dst;            ///< Destination IP address (IPv4 only)
    
    // Layer 4 metadata
    uint16_t port_src;          ///< Source port
    uint16_t port_dst;          ///< Destination port
    
    // TCP specific metadata
    uint32_t tcp_seq;           ///< TCP sequence number
    uint32_t tcp_ack;           ///< TCP acknowledgment number
    uint8_t tcp_flags;          ///< TCP flags
};

/**
 * @brief Base class for packet handlers
 */
class PacketHandler {
public:
    virtual ~PacketHandler() = default;
    
    /**
     * @brief Process a single packet
     * @param packet The packet to process
     * @return true if the packet should continue to the next handler, false to stop
     */
    virtual bool handlePacket(const Packet& packet) = 0;
    
    /**
     * @brief Process a batch of packets
     * @param packets Vector of packets to process
     * @return Vector of packets that should continue to the next handler
     */
    virtual std::vector<Packet> handlePacketBatch(const std::vector<Packet>& packets);
};

/**
 * @brief Statistics for the packet processor
 */
struct PacketProcessorStats {
    uint64_t packets_captured;          ///< Total packets captured
    uint64_t packets_processed;         ///< Total packets processed
    uint64_t packets_dropped_pcap;      ///< Packets dropped by libpcap
    uint64_t packets_dropped_buffer;    ///< Packets dropped due to full buffer
    uint64_t bytes_processed;           ///< Total bytes processed
    double packets_per_second;          ///< Current packets per second rate
    double mbps;                        ///< Current throughput in Mbps
    double cpu_usage;                   ///< Current CPU usage percentage
    uint64_t avg_processing_ns;         ///< Average processing time in nanoseconds
};

// Forward declarations
class PacketCapture;
class ThreadPool;
class ZeroCopyBuffer;
class ProtocolParser;
class ConnectionTracker;
class Statistics;
class Logger;

/**
 * @brief Main packet processor engine class
 */
class PacketProcessor {
public:
    /**
     * @brief Construct a new Packet Processor with the given configuration
     * @param config Configuration for the packet processor
     */
    explicit PacketProcessor(const PacketProcessorConfig& config);
    
    /**
     * @brief Destructor
     */
    ~PacketProcessor();
    
    /**
     * @brief Initialize the packet processor
     * @return true if initialization was successful
     */
    bool initialize();
    
    /**
     * @brief Start packet capture and processing
     * @return true if started successfully
     */
    bool start();
    
    /**
     * @brief Stop packet capture and processing
     */
    void stop();
    
    /**
     * @brief Add a packet handler to the processing pipeline
     * @param handler The handler to add
     */
    void addHandler(std::shared_ptr<PacketHandler> handler);
    
    /**
     * @brief Get current statistics
     * @return Current statistics
     */
    PacketProcessorStats getStatistics() const;
    
    /**
     * @brief Set statistics callback function
     * @param callback Function to call with statistics at regular intervals
     */
    void setStatisticsCallback(std::function<void(const PacketProcessorStats&)> callback);
    
private:
    PacketProcessorConfig config_;
    
    std::unique_ptr<PacketCapture> capture_;
    std::unique_ptr<ThreadPool> thread_pool_;
    std::unique_ptr<ZeroCopyBuffer> buffer_;
    std::unique_ptr<ProtocolParser> parser_;
    std::unique_ptr<ConnectionTracker> tracker_;
    std::unique_ptr<Statistics> statistics_;
    std::unique_ptr<Logger> logger_;
    
    std::vector<std::shared_ptr<PacketHandler>> handlers_;
    
    bool is_running_ = false;
    
    // Internal processing functions
    void processingLoop();
    void processPacketBatch(const std::vector<Packet>& packets);
};

} // namespace packet_processor 