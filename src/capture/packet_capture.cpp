#include "packet_processor/capture/packet_capture.h"
#include "packet_processor/core/packet.h"
#include <iostream>
#include <cstring>
#include <chrono>
#include <thread>
#include <cstdlib>
#include <sys/types.h>
#include <sys/sysctl.h>

// macOS specific headers for BPF operations
#ifdef __APPLE__
#include <unistd.h>
#include <sys/ioctl.h>

// Define the BPF ioctl commands we need directly
// to avoid including net/bpf.h which conflicts with pcap/bpf.h
#ifndef BIOCSBLEN
#define BIOCSBLEN _IOWR('B', 102, u_int)
#endif
#ifndef BIOCIMMEDIATE
#define BIOCIMMEDIATE _IOW('B', 112, u_int)
#endif
#endif

namespace packet_processor {

PacketCapture::PacketCapture(const std::string& device_name, 
                           int buffer_size, 
                           int snaplen, 
                           bool promiscuous,
                           ZeroCopyBuffer* buffer)
    : device_name_(device_name),
      buffer_size_(buffer_size),
      snaplen_(snaplen),
      promiscuous_(promiscuous),
      buffer_(buffer),
      running_(false) {
}

PacketCapture::~PacketCapture() {
    // Stop capture if it's running
    stop();
    
    // Close pcap handle
    if (pcap_handle_) {
        pcap_close(pcap_handle_);
        pcap_handle_ = nullptr;
    }
}

bool PacketCapture::initialize() {
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    
    // Open device for capture
    pcap_handle_ = pcap_create(device_name_.c_str(), errbuf);
    if (!pcap_handle_) {
        std::cerr << "Failed to open device " << device_name_ << ": " << errbuf << std::endl;
        return false;
    }
    
    // Set capture parameters
    if (pcap_set_snaplen(pcap_handle_, snaplen_) != 0) {
        std::cerr << "Failed to set snaplen: " << pcap_geterr(pcap_handle_) << std::endl;
        return false;
    }
    
    if (pcap_set_promisc(pcap_handle_, promiscuous_ ? 1 : 0) != 0) {
        std::cerr << "Failed to set promiscuous mode: " << pcap_geterr(pcap_handle_) << std::endl;
        return false;
    }
    
    // Set buffer size
    if (pcap_set_buffer_size(pcap_handle_, buffer_size_) != 0) {
        std::cerr << "Failed to set buffer size: " << pcap_geterr(pcap_handle_) << std::endl;
        return false;
    }
    
    // Set immediate mode (packets are delivered as soon as they arrive)
    if (pcap_set_immediate_mode(pcap_handle_, 1) != 0) {
        std::cerr << "Failed to set immediate mode: " << pcap_geterr(pcap_handle_) << std::endl;
        return false;
    }
    
    // Activate the capture handle
    if (pcap_activate(pcap_handle_) != 0) {
        std::cerr << "Failed to activate capture: " << pcap_geterr(pcap_handle_) << std::endl;
        return false;
    }
    
    // Apply macOS specific optimizations
    if (!optimizeForMacOS()) {
        std::cerr << "Warning: Failed to apply macOS specific optimizations" << std::endl;
        // Continue anyway, not a fatal error
    }
    
    return true;
}

bool PacketCapture::setFilter(const std::string& filter) {
    if (!pcap_handle_ || filter.empty()) {
        return false;
    }
    
    // Compile filter
    bpf_program fp;
    if (pcap_compile(pcap_handle_, &fp, filter.c_str(), 1, PCAP_NETMASK_UNKNOWN) != 0) {
        std::cerr << "Failed to compile filter: " << pcap_geterr(pcap_handle_) << std::endl;
        return false;
    }
    
    // Apply filter
    if (pcap_setfilter(pcap_handle_, &fp) != 0) {
        std::cerr << "Failed to set filter: " << pcap_geterr(pcap_handle_) << std::endl;
        pcap_freecode(&fp);
        return false;
    }
    
    // Free compiled filter
    pcap_freecode(&fp);
    
    return true;
}

bool PacketCapture::start() {
    if (!pcap_handle_ || running_) {
        return false;
    }
    
    // Set running flag
    running_ = true;
    
    // Start capture thread
    capture_thread_ = std::thread(&PacketCapture::captureLoop, this);
    
    return true;
}

void PacketCapture::stop() {
    // Set running flag to false
    running_ = false;
    
    // Break out of pcap_loop by sending a signal to the thread
    if (pcap_handle_) {
        pcap_breakloop(pcap_handle_);
    }
    
    // Wait for capture thread to finish
    if (capture_thread_.joinable()) {
        capture_thread_.join();
    }
}

CaptureStats PacketCapture::getStatistics() const {
    CaptureStats stats = {0};
    
    if (pcap_handle_) {
        struct pcap_stat pcap_stats;
        if (::pcap_stats(pcap_handle_, &pcap_stats) == 0) {
            stats.packets_captured = pcap_stats.ps_recv;
            stats.packets_dropped = pcap_stats.ps_drop;
            stats.packets_if_dropped = pcap_stats.ps_ifdrop;
        }
    }
    
    return stats;
}

std::vector<std::string> PacketCapture::getDeviceNames() {
    std::vector<std::string> result;
    
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_if_t* alldevs;
    
    // Get list of devices
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Error finding devices: " << errbuf << std::endl;
        return result;
    }
    
    // Iterate through devices
    for (pcap_if_t* dev = alldevs; dev; dev = dev->next) {
        result.push_back(dev->name);
    }
    
    // Free device list
    pcap_freealldevs(alldevs);
    
    return result;
}

void PacketCapture::captureLoop() {
    // Set thread priority to real-time for capture thread
#ifdef __APPLE__
    // Set to real-time priority on macOS
    struct sched_param param;
    param.sched_priority = 96; // High real-time priority (0-99)
    if (pthread_setschedparam(pthread_self(), SCHED_RR, &param) != 0) {
        std::cerr << "Warning: Failed to set thread priority" << std::endl;
    }
#endif
    
    // Capture packets in a loop
    while (running_) {
        // Get a buffer to store packets
        RingBufferEntry* buffer_entry = buffer_->getWriteBuffer();
        if (!buffer_entry) {
            // No buffer available, wait and try again
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            continue;
        }
        
        // Get buffer ID - fix incorrect expression
        uint32_t buffer_id = static_cast<uint32_t>(buffer_entry - buffer_->getBuffers());
        
        // Capture a batch of packets
        int ret = pcap_loop(pcap_handle_, -1, 
            [](u_char* user, const struct pcap_pkthdr* header, const u_char* packet) {
                // Get the capture object
                PacketCapture* capture = reinterpret_cast<PacketCapture*>(user);
                
                // Process the packet
                capture->processPacket(header, packet);
            }, 
            reinterpret_cast<u_char*>(this));
        
        // Check if we were interrupted
        if (ret == PCAP_ERROR_BREAK) {
            // Interrupted by pcap_breakloop, check if we should continue
            if (!running_) {
                break;
            }
        } else if (ret < 0) {
            // Error
            std::cerr << "Error in packet capture: " << pcap_geterr(pcap_handle_) << std::endl;
            break;
        }
        
        // Release buffer
        buffer_->releaseWriteBuffer(buffer_id);
    }
}

bool PacketCapture::optimizeForMacOS() {
#ifdef __APPLE__
    // On macOS, we can use BPF optimizations
    
    // Get the BPF file descriptor
    int fd = pcap_fileno(pcap_handle_);
    if (fd < 0) {
        return false;
    }
    
    // Set BPF buffer length to match our buffer size
    // This helps reduce packet drops
    unsigned int buflen = buffer_size_;
    if (::ioctl(fd, BIOCSBLEN, &buflen) < 0) {
        perror("BIOCSBLEN");
        return false;
    }
    
    // Set immediate mode to reduce latency
    // This is especially important for high-speed capture
    int immediate = 1;
    if (::ioctl(fd, BIOCIMMEDIATE, &immediate) < 0) {
        perror("BIOCIMMEDIATE");
        return false;
    }
    
    // On Apple Silicon, apply additional optimizations
    if (isAppleSilicon()) {
        // The BIOCSTSTAMP ioctl is not available on all macOS versions
        // We'll skip this optimization to avoid compatibility issues
    }
    
    return true;
#else
    // Not macOS
    return false;
#endif
}

void PacketCapture::processPacket(const struct pcap_pkthdr* header, const u_char* data) {
    // Get buffer to store packet
    RingBufferEntry* buffer_entry = buffer_->getWriteBuffer();
    if (!buffer_entry) {
        // No buffer available, drop packet
        return;
    }
    
    // Check if packet fits in buffer
    if (buffer_entry->size + header->caplen > buffer_entry->capacity) {
        // Packet too large, drop it
        return;
    }
    
    // Copy packet data to buffer
    memcpy(buffer_entry->data + buffer_entry->size, data, header->caplen);
    
    // Update buffer size
    buffer_entry->size += header->caplen;
    
    // Get timestamp
    uint64_t timestamp = header->ts.tv_sec * 1000000ULL + header->ts.tv_usec;
    
    // Create packet structure pointing to the data in the buffer
    Packet packet;
    packet.data = buffer_entry->data + buffer_entry->size - header->caplen;
    packet.length = header->caplen;
    packet.timestamp = timestamp;
    packet.buffer_id = static_cast<uint32_t>(buffer_entry - buffer_->getBuffers());
    
    // Initialize metadata fields
    packet.eth_type = 0;
    packet.ip_version = 0;
    packet.ip_protocol = 0;
    packet.ip_src = 0;
    packet.ip_dst = 0;
    packet.port_src = 0;
    packet.port_dst = 0;
    packet.tcp_seq = 0;
    packet.tcp_ack = 0;
    packet.tcp_flags = 0;
}

bool PacketCapture::isAppleSilicon() {
#ifdef __APPLE__
    char buffer[256];
    size_t size = sizeof(buffer);
    
    // Check CPU type using sysctl
    if (sysctlbyname("machdep.cpu.brand_string", buffer, &size, nullptr, 0) == 0) {
        // Check if the brand string contains "Apple"
        return strstr(buffer, "Apple") != nullptr;
    }
#endif
    
    // Default to false
    return false;
}

} // namespace packet_processor 