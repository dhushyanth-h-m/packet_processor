#include "packet_processor/processing/zero_copy_buffer.h"
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <iostream>
#include <chrono>

namespace packet_processor {

ZeroCopyBuffer::ZeroCopyBuffer(uint32_t buffer_size, uint32_t buffer_count)
    : buffer_size_(buffer_size), 
      buffer_count_(buffer_count),
      overflow_count_(0) {
}

ZeroCopyBuffer::~ZeroCopyBuffer() {
    // Clean up memory-mapped regions
    for (size_t i = 0; i < buffers_.size(); ++i) {
        if (buffers_[i].data) {
            releaseMappedMemory(buffers_[i].data, buffer_size_, mmap_fds_[i]);
        }
    }
}

bool ZeroCopyBuffer::initialize() {
    // Initialize buffers
    buffers_.resize(buffer_count_);
    mmap_fds_.resize(buffer_count_);
    
    // Create memory-mapped regions for each buffer
    for (uint32_t i = 0; i < buffer_count_; ++i) {
        // Create memory-mapped region
        uint8_t* data = createMappedMemory(buffer_size_);
        if (!data) {
            // Clean up already created regions
            for (uint32_t j = 0; j < i; ++j) {
                releaseMappedMemory(buffers_[j].data, buffer_size_, mmap_fds_[j]);
                buffers_[j].data = nullptr;
            }
            return false;
        }
        
        // Initialize buffer entry
        buffers_[i].data = data;
        buffers_[i].capacity = buffer_size_;
        buffers_[i].size = 0;
        buffers_[i].in_use = false;
    }
    
    return true;
}

RingBufferEntry* ZeroCopyBuffer::getWriteBuffer() {
    std::unique_lock<std::mutex> lock(write_mutex_);
    
    // Find a buffer that is not in use
    for (uint32_t i = 0; i < buffer_count_; ++i) {
        if (!buffers_[i].in_use) {
            // Reset buffer state
            buffers_[i].size = 0;
            buffers_[i].in_use = true;
            return &buffers_[i];
        }
    }
    
    // No buffer available, wait for one to become available
    bool buffer_available = write_cv_.wait_for(lock, std::chrono::milliseconds(100),
        [this]() {
            for (uint32_t i = 0; i < buffer_count_; ++i) {
                if (!buffers_[i].in_use) {
                    return true;
                }
            }
            return false;
        });
    
    if (buffer_available) {
        // Find the available buffer
        for (uint32_t i = 0; i < buffer_count_; ++i) {
            if (!buffers_[i].in_use) {
                // Reset buffer state
                buffers_[i].size = 0;
                buffers_[i].in_use = true;
                return &buffers_[i];
            }
        }
    }
    
    // Increment overflow count if we couldn't get a buffer
    ++overflow_count_;
    return nullptr;
}

void ZeroCopyBuffer::releaseWriteBuffer(uint32_t buffer_id) {
    if (buffer_id >= buffer_count_) {
        return;
    }
    
    // Buffer is now ready for reading
    read_cv_.notify_one();
}

RingBufferEntry* ZeroCopyBuffer::getReadBuffer() {
    std::unique_lock<std::mutex> lock(read_mutex_);
    
    // Find a buffer that is in use and has data
    for (uint32_t i = 0; i < buffer_count_; ++i) {
        if (buffers_[i].in_use && buffers_[i].size > 0) {
            return &buffers_[i];
        }
    }
    
    // No buffer available, wait for one to become available
    bool buffer_available = read_cv_.wait_for(lock, std::chrono::milliseconds(100),
        [this]() {
            for (uint32_t i = 0; i < buffer_count_; ++i) {
                if (buffers_[i].in_use && buffers_[i].size > 0) {
                    return true;
                }
            }
            return false;
        });
    
    if (buffer_available) {
        // Find the available buffer
        for (uint32_t i = 0; i < buffer_count_; ++i) {
            if (buffers_[i].in_use && buffers_[i].size > 0) {
                return &buffers_[i];
            }
        }
    }
    
    return nullptr;
}

void ZeroCopyBuffer::releaseReadBuffer(uint32_t buffer_id) {
    if (buffer_id >= buffer_count_) {
        return;
    }
    
    // Mark buffer as no longer in use
    buffers_[buffer_id].in_use = false;
    
    // Buffer is now available for writing
    write_cv_.notify_one();
}

uint8_t* ZeroCopyBuffer::createMappedMemory(size_t size) {
    // On macOS, we use a temporary file for shared memory
    char file_template[] = "/tmp/packet_processor_buffer_XXXXXX";
    int fd = mkstemp(file_template);
    if (fd == -1) {
        perror("Failed to create temporary file for memory mapping");
        return nullptr;
    }
    
    // Immediately unlink the file so it's removed when the process exits
    if (unlink(file_template) == -1) {
        perror("Failed to unlink temporary file");
        close(fd);
        return nullptr;
    }
    
    // Set the file size
    if (ftruncate(fd, size) == -1) {
        perror("Failed to set file size");
        close(fd);
        return nullptr;
    }
    
    // Memory map the file
    uint8_t* data = static_cast<uint8_t*>(mmap(
        nullptr,                  // Let the system choose the address
        size,                     // Size of the mapping
        PROT_READ | PROT_WRITE,   // Read/write access
        MAP_SHARED,               // Shared mapping (visible to other processes)
        fd,                       // File descriptor
        0                         // Offset
    ));
    
    if (data == MAP_FAILED) {
        perror("Failed to memory map file");
        close(fd);
        return nullptr;
    }
    
    // Store the file descriptor for later cleanup
    mmap_fds_.push_back(fd);
    
    // On Apple Silicon, optimize for performance
#ifdef APPLE_SILICON
    // Advise that this memory will be accessed sequentially
    if (posix_madvise(data, size, POSIX_MADV_SEQUENTIAL) != 0) {
        perror("Failed to set memory advice");
    }
    
    // Advise that this memory will be accessed with high temporal locality
    if (posix_madvise(data, size, POSIX_MADV_WILLNEED) != 0) {
        perror("Failed to set memory advice");
    }
#endif
    
    return data;
}

void ZeroCopyBuffer::releaseMappedMemory(uint8_t* ptr, size_t size, int fd) {
    if (ptr) {
        // Unmap the memory region
        if (munmap(ptr, size) == -1) {
            perror("Failed to unmap memory");
        }
    }
    
    if (fd != -1) {
        // Close the file descriptor
        close(fd);
    }
}

} // namespace packet_processor 