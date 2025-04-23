# High-Throughput Packet Processing Engine

A high-performance packet processing engine designed for macOS, optimized for both Intel and Apple Silicon architectures.

## Features

- **High Performance**: Capture and process 1M+ packets per second
- **Zero-Copy Architecture**: Minimizes CPU usage with memory-mapped buffers
- **Multi-Threaded Processing**: Efficiently utilizes multi-core CPUs
- **Protocol Parsing**: Fast packet header parsing for all common protocols
- **Connection Tracking**: Track 10,000+ concurrent connections
- **MacOS Optimized**: Platform-specific optimizations for both Intel and Apple Silicon
- **Comprehensive Statistics**: Real-time performance metrics and analysis
- **Modular Design**: Easily extensible for custom packet processing

## Requirements

- macOS 11.0 or higher (Big Sur+)
- CMake 3.14 or higher
- Clang or GCC with C++17 support
- libpcap (typically pre-installed on macOS)
- Administrator privileges (for packet capture)

## Building

Clone the repository and build with CMake:

```bash
git clone https://github.com/yourusername/packet-processor.git
cd packet-processor
mkdir build && cd build
cmake ..
make
```

## Usage

The library can be used as a standalone command-line tool or integrated into your own C++ applications.

### Command-Line Tool

```bash
# Basic packet capture
sudo ./packet_processor -i en0

# With BPF filter
sudo ./packet_processor -i en0 -f "tcp port 80"

# List available interfaces
./packet_processor -L
```

### Library Integration

```cpp
#include "packet_processor/packet_processor.h"

// Configure the packet processor
packet_processor::PacketProcessorConfig config;
config.device_name = "en0";
config.capture_buffer_size = 2 * 1024 * 1024;
config.promiscuous_mode = true;

// Create packet processor
packet_processor::PacketProcessor processor(config);

// Add a custom packet handler
class MyPacketHandler : public packet_processor::PacketHandler {
public:
    bool handlePacket(const packet_processor::Packet& packet) override {
        // Process packet here
        return true;
    }
};

auto handler = std::make_shared<MyPacketHandler>();
processor.addHandler(handler);

// Initialize and start
processor.initialize();
processor.start();

// ... do other work or wait ...

// Stop when done
processor.stop();
```

## Examples

The following examples are included:

- **basic_capture**: Simple packet capture and analysis
- **connection_monitor**: Track and display active network connections
- **protocol_analyzer**: Analyze protocol distribution in network traffic

Run the examples:

```bash
sudo ./examples/basic_capture en0
sudo ./examples/connection_monitor en0
sudo ./examples/protocol_analyzer en0
```

## Benchmarking

A comprehensive benchmarking tool is included to measure performance:

```bash
sudo ./benchmark en0 -t 60 -o results.txt
```

Options:
- `-f, --filter <filter>`: BPF filter to use
- `-t, --time <seconds>`: Benchmark duration in seconds (default: 60)
- `-c, --count-only`: Only count packets, don't process them
- `-o, --output <filename>`: Output file for results
- `-p, --processing-threads <num>`: Number of processing threads (default: auto)

## Performance Tuning

For optimal performance:

1. **Buffer Sizes**: Adjust `capture_buffer_size` and `zero_copy_buffer_size` based on available memory
2. **Thread Count**: Set `processing_threads` to match your CPU architecture
3. **BPF Filters**: Use efficient BPF filters to reduce processing overhead
4. **Ring Buffer Count**: Increase `ring_buffer_count` for higher throughput scenarios
5. **Real-time Priority**: On supported systems, enable real-time thread priority

## Architecture

The packet processor consists of several key components:

1. **Packet Capture**: Uses libpcap with macOS-specific optimizations
2. **Zero-Copy Buffer**: Memory-mapped ring buffers for efficient data transfer
3. **Thread Pool**: Multi-threaded processing architecture optimized for macOS
4. **Protocol Parser**: Fast packet header parsing for common protocols
5. **Connection Tracker**: Efficient tracking of concurrent connections
6. **Statistics**: Comprehensive performance metrics collection

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgements

- libpcap developers
- Apple's Darwin networking team
- The open-source networking community

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. 