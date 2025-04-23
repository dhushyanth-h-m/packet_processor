#pragma once

#include <cstdint>
#include <vector>
#include <atomic>
#include <mutex>

namespace packet_processor {

/**
 * Structure representing an entry in the ring buffer
 */
struct RingBufferEntry {
    // Pointer to data buffer
    uint8_t* data;
    
    // Current size of data in the buffer
    uint32_t size;
    
    // Total capacity of the buffer
    uint32_t capacity;
    
    // Flag indicating if the buffer is in use
    bool in_use;
};

/**
 * Zero-copy buffer implementation for efficient packet processing.
 * This class manages a pool of buffers that can be used for packet capture
 * and processing without unnecessary memory copies.
 */
class ZeroCopyBuffer {
public:
    /**
     * Constructor
     * 
     * @param buffer_count Number of buffers to allocate
     * @param buffer_size Size of each buffer in bytes
     */
    ZeroCopyBuffer(uint32_t buffer_count, uint32_t buffer_size);
    
    /**
     * Destructor
     */
    ~ZeroCopyBuffer();
    
    /**
     * Get a buffer for writing
     * 
     * @return Pointer to a buffer entry, or nullptr if no buffers are available
     */
    RingBufferEntry* getWriteBuffer();
    
    /**
     * Release a write buffer
     * 
     * @param buffer_id ID of the buffer to release
     */
    void releaseWriteBuffer(uint32_t buffer_id);
    
    /**
     * Get a buffer for reading
     * 
     * @return Pointer to a buffer entry, or nullptr if no buffers are available
     */
    RingBufferEntry* getReadBuffer();
    
    /**
     * Release a read buffer
     * 
     * @param buffer_id ID of the buffer to release
     */
    void releaseReadBuffer(uint32_t buffer_id);
    
    /**
     * Get pointers to all buffers
     * 
     * @return Pointer to the first buffer (for pointer arithmetic)
     */
    RingBufferEntry* getBuffers() { return buffers_.data(); }
    
    /**
     * Get the number of buffers
     * 
     * @return Number of buffers
     */
    uint32_t getBufferCount() const { return static_cast<uint32_t>(buffers_.size()); }

private:
    // Vector of buffer entries
    std::vector<RingBufferEntry> buffers_;
    
    // Mutex for thread safety
    std::mutex mutex_;
    
    // Index for the next write buffer
    uint32_t write_index_;
    
    // Index for the next read buffer
    uint32_t read_index_;
};

} // namespace packet_processor 