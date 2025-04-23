#include <iostream>
#include <string>
#include <csignal>
#include <chrono>
#include <thread>
#include <vector>
#include <iomanip>

#include "packet_processor/packet_processor.h"

// Global variables for signal handling
static bool running = true;
static packet_processor::PacketProcessor* processor = nullptr;

// Signal handler for graceful shutdown
void signalHandler(int signal) {
    if (signal == SIGINT || signal == SIGTERM) {
        std::cout << "\nShutting down packet processor..." << std::endl;
        running = false;
        if (processor) {
            processor->stop();
        }
    }
}

// Print statistics callback
void printStatistics(const packet_processor::PacketProcessorStats& stats) {
    // Clear terminal
    std::cout << "\033[2J\033[1;1H";
    
    // Print header
    std::cout << "======== Packet Processor Statistics ========" << std::endl;
    
    // Print statistics
    std::cout << std::fixed << std::setprecision(2);
    std::cout << "Packets Captured: " << stats.packets_captured << std::endl;
    std::cout << "Packets Processed: " << stats.packets_processed << std::endl;
    std::cout << "Packets Dropped (pcap): " << stats.packets_dropped_pcap << std::endl;
    std::cout << "Packets Dropped (buffer): " << stats.packets_dropped_buffer << std::endl;
    std::cout << "Bytes Processed: " << stats.bytes_processed << std::endl;
    std::cout << "Throughput: " << stats.packets_per_second << " pps / " << stats.mbps << " Mbps" << std::endl;
    std::cout << "CPU Usage: " << stats.cpu_usage << "%" << std::endl;
    std::cout << "Avg Processing Time: " << stats.avg_processing_ns << " ns/packet" << std::endl;
    
    // Print footer
    std::cout << "=============================================" << std::endl;
    std::cout << "Press Ctrl+C to exit" << std::endl;
}

// Print available devices
void printAvailableDevices() {
    std::vector<std::string> devices = packet_processor::PacketCapture::getDeviceNames();
    
    std::cout << "Available network interfaces:" << std::endl;
    for (const auto& device : devices) {
        std::cout << "  - " << device << std::endl;
    }
    std::cout << std::endl;
}

// Print usage
void printUsage(const char* programName) {
    std::cout << "Usage: " << programName << " [options]" << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  -i, --interface <interface>  Network interface to capture from" << std::endl;
    std::cout << "  -b, --buffer-size <size>     Capture buffer size in MB (default: 2)" << std::endl;
    std::cout << "  -z, --zero-copy-size <size>  Zero-copy buffer size in MB (default: 4)" << std::endl;
    std::cout << "  -r, --ring-buffers <count>   Number of ring buffers (default: 8)" << std::endl;
    std::cout << "  -t, --threads <count>        Number of processing threads (default: auto)" << std::endl;
    std::cout << "  -f, --filter <filter>        BPF filter (e.g., \"tcp port 80\")" << std::endl;
    std::cout << "  -p, --promiscuous            Enable promiscuous mode" << std::endl;
    std::cout << "  -l, --log-level <level>      Log level (debug, info, warning, error)" << std::endl;
    std::cout << "  -L, --list-interfaces        List available network interfaces" << std::endl;
    std::cout << "  -h, --help                   Show this help message" << std::endl;
}

// Parse command line arguments
packet_processor::PacketProcessorConfig parseCommandLine(int argc, char* argv[]) {
    packet_processor::PacketProcessorConfig config;
    
    // Set defaults
    config.device_name = "";
    config.capture_buffer_size = 2 * 1024 * 1024;  // 2 MB
    config.zero_copy_buffer_size = 4 * 1024 * 1024;  // 4 MB
    config.ring_buffer_count = 8;
    config.processing_threads = 0;  // Auto-detect
    config.bpf_filter = "";
    config.promiscuous_mode = false;
    config.log_level = "info";
    
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        
        if (arg == "-i" || arg == "--interface") {
            if (i + 1 < argc) {
                config.device_name = argv[++i];
            }
        } else if (arg == "-b" || arg == "--buffer-size") {
            if (i + 1 < argc) {
                config.capture_buffer_size = std::stoi(argv[++i]) * 1024 * 1024;
            }
        } else if (arg == "-z" || arg == "--zero-copy-size") {
            if (i + 1 < argc) {
                config.zero_copy_buffer_size = std::stoi(argv[++i]) * 1024 * 1024;
            }
        } else if (arg == "-r" || arg == "--ring-buffers") {
            if (i + 1 < argc) {
                config.ring_buffer_count = std::stoi(argv[++i]);
            }
        } else if (arg == "-t" || arg == "--threads") {
            if (i + 1 < argc) {
                config.processing_threads = std::stoi(argv[++i]);
            }
        } else if (arg == "-f" || arg == "--filter") {
            if (i + 1 < argc) {
                config.bpf_filter = argv[++i];
            }
        } else if (arg == "-p" || arg == "--promiscuous") {
            config.promiscuous_mode = true;
        } else if (arg == "-l" || arg == "--log-level") {
            if (i + 1 < argc) {
                config.log_level = argv[++i];
            }
        } else if (arg == "-L" || arg == "--list-interfaces") {
            printAvailableDevices();
            exit(0);
        } else if (arg == "-h" || arg == "--help") {
            printUsage(argv[0]);
            exit(0);
        }
    }
    
    // Validate configuration
    if (config.device_name.empty()) {
        std::cerr << "Error: No interface specified" << std::endl;
        printUsage(argv[0]);
        exit(1);
    }
    
    return config;
}

// Custom packet handler example
class ExamplePacketHandler : public packet_processor::PacketHandler {
public:
    bool handlePacket(const packet_processor::Packet& packet) override {
        // This is just an example handler that could be expanded
        // For now, it just allows all packets to continue to the next handler
        return true;
    }
};

int main(int argc, char* argv[]) {
    // Register signal handlers
    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);
    
    // Parse command line arguments
    packet_processor::PacketProcessorConfig config = parseCommandLine(argc, argv);
    
    // Create packet processor
    processor = new packet_processor::PacketProcessor(config);
    
    // Register statistics callback
    processor->setStatisticsCallback(printStatistics);
    
    // Add custom packet handler
    auto handler = std::make_shared<ExamplePacketHandler>();
    processor->addHandler(handler);
    
    // Initialize the processor
    if (!processor->initialize()) {
        std::cerr << "Failed to initialize packet processor" << std::endl;
        delete processor;
        return 1;
    }
    
    // Start the processor
    if (!processor->start()) {
        std::cerr << "Failed to start packet processor" << std::endl;
        delete processor;
        return 1;
    }
    
    std::cout << "Packet processor started on interface " << config.device_name << std::endl;
    std::cout << "Press Ctrl+C to exit" << std::endl;
    
    // Main loop
    while (running) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    // Cleanup
    delete processor;
    processor = nullptr;
    
    std::cout << "Packet processor stopped" << std::endl;
    return 0;
} 