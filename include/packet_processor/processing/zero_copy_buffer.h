#pragma once

#include <vector>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <memory>
#include <cstdint>
#include <sys/mman.h>

namespace packet_processor {

/**
 * @brief A ring buffer entry for packet data
 */
struct RingBufferEntry {
    uint8_t* data;              ///< Pointer to the data
    uint32_t capacity;          ///< Total capacity of the buffer
    std::atomic<uint32_t> size; ///< Current size of the buffer
    std::atomic<bool> in_use;   ///< Whether the buffer is currently in use
};

/**
 * @brief Zero-copy buffer implementation using memory mapping for efficient packet processing
 * 
 * This class implements a ring buffer system using memory-mapped files to achieve
 * zero-copy packet processing. This reduces CPU usage by minimizing memory copies
 * and context switches.
 */
class ZeroCopyBuffer {
public:
    /**
     * @brief Construct a new Zero Copy Buffer
     * 
     * @param buffer_size Size of each buffer in bytes
     * @param buffer_count Number of buffers in the ring
     */
    ZeroCopyBuffer(uint32_t buffer_size, uint32_t buffer_count);
    
    /**
     * @brief Destructor - cleans up memory-mapped regions
     */
    ~ZeroCopyBuffer();
    
    /**
     * @brief Initialize the buffer system
     * 
     * @return true if initialization was successful
     */
    bool initialize();
    
    /**
     * @brief Get a buffer for capturing packets
     * 
     * @return Pointer to a buffer entry or nullptr if none available
     */
    RingBufferEntry* getWriteBuffer();
    
    /**
     * @brief Release a write buffer after capturing packets
     * 
     * @param buffer_id ID of the buffer to release
     */
    void releaseWriteBuffer(uint32_t buffer_id);
    
    /**
     * @brief Get a buffer for processing packets
     * 
     * @return Pointer to a buffer entry or nullptr if none available
     */
    RingBufferEntry* getReadBuffer();
    
    /**
     * @brief Release a read buffer after processing packets
     * 
     * @param buffer_id ID of the buffer to release
     */
    void releaseReadBuffer(uint32_t buffer_id);
    
    /**
     * @brief Get the total number of buffers
     * 
     * @return Number of buffers
     */
    uint32_t getBufferCount() const { return buffer_count_; }
    
    /**
     * @brief Get the size of each buffer
     * 
     * @return Size of each buffer in bytes
     */
    uint32_t getBufferSize() const { return buffer_size_; }
    
    /**
     * @brief Get the number of buffer overflows
     * 
     * @return Number of buffer overflows
     */
    uint64_t getOverflowCount() const { return overflow_count_; }
    
private:
    const uint32_t buffer_size_;    ///< Size of each buffer in bytes
    const uint32_t buffer_count_;   ///< Number of buffers in the ring
    
    std::vector<RingBufferEntry> buffers_;  ///< Vector of buffer entries
    std::vector<int> mmap_fds_;              ///< File descriptors for mmap
    
    std::mutex write_mutex_;                ///< Mutex for write operations
    std::mutex read_mutex_;                 ///< Mutex for read operations
    std::condition_variable write_cv_;      ///< Condition variable for write operations
    std::condition_variable read_cv_;       ///< Condition variable for read operations
    
    std::atomic<uint64_t> overflow_count_;  ///< Count of buffer overflows
    
    /**
     * @brief Create a memory-mapped region for zero-copy
     * 
     * @param size Size of the region in bytes
     * @return Pointer to the mapped memory or nullptr on failure
     */
    uint8_t* createMappedMemory(size_t size);
    
    /**
     * @brief Release a memory-mapped region
     * 
     * @param ptr Pointer to the mapped memory
     * @param size Size of the region in bytes
     * @param fd File descriptor for the mapped memory
     */
    void releaseMappedMemory(uint8_t* ptr, size_t size, int fd);
};

} // namespace packet_processor 