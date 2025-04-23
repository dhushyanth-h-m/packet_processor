#pragma once

#include <string>
#include <thread>
#include <atomic>
#include <pcap.h>
#include "packet_processor/core/zero_copy_buffer.h"

namespace packet_processor {

/**
 * Structure containing capture statistics
 */
struct CaptureStats {
    // Number of packets captured
    uint64_t packets_captured;
    
    // Number of packets dropped by the kernel
    uint64_t packets_dropped;
    
    // Number of packets dropped by the interface
    uint64_t packets_if_dropped;
};

/**
 * Class for capturing network packets using libpcap
 */
class PacketCapture {
public:
    /**
     * Constructor
     * 
     * @param device_name Name of the network device to capture from
     * @param buffer_size Size of the capture buffer in bytes
     * @param snaplen Maximum length of each packet to capture
     * @param promiscuous Whether to put the device in promiscuous mode
     * @param buffer Pointer to a zero-copy buffer for storing captured packets
     */
    PacketCapture(const std::string& device_name, 
                  int buffer_size, 
                  int snaplen, 
                  bool promiscuous,
                  ZeroCopyBuffer* buffer);
    
    /**
     * Destructor
     */
    ~PacketCapture();
    
    /**
     * Initialize the packet capture
     * 
     * @return True if initialization succeeded, false otherwise
     */
    bool initialize();
    
    /**
     * Set a BPF filter for the capture
     * 
     * @param filter BPF filter string
     * @return True if the filter was set successfully, false otherwise
     */
    bool setFilter(const std::string& filter);
    
    /**
     * Start capturing packets
     * 
     * @return True if capture was started successfully, false otherwise
     */
    bool start();
    
    /**
     * Stop capturing packets
     */
    void stop();
    
    /**
     * Get capture statistics
     * 
     * @return Structure containing capture statistics
     */
    CaptureStats getStatistics() const;
    
    /**
     * Get a list of available capture devices
     * 
     * @return Vector of device names
     */
    static std::vector<std::string> getDeviceNames();

private:
    /**
     * Main capture loop
     */
    void captureLoop();
    
    /**
     * Process a captured packet
     * 
     * @param header Packet header
     * @param data Packet data
     */
    void processPacket(const struct pcap_pkthdr* header, const u_char* data);
    
    /**
     * Apply macOS-specific optimizations
     * 
     * @return True if optimizations were applied successfully, false otherwise
     */
    bool optimizeForMacOS();
    
    /**
     * Check if running on Apple Silicon
     * 
     * @return True if running on Apple Silicon, false otherwise
     */
    bool isAppleSilicon();
    
private:
    // Device name
    std::string device_name_;
    
    // Buffer size
    int buffer_size_;
    
    // Snapshot length
    int snaplen_;
    
    // Promiscuous mode flag
    bool promiscuous_;
    
    // Pointer to zero-copy buffer
    ZeroCopyBuffer* buffer_;
    
    // Running flag
    std::atomic<bool> running_;
    
    // Capture thread
    std::thread capture_thread_;
    
    // Pcap handle
    pcap_t* pcap_handle_ = nullptr;
};

} // namespace packet_processor 