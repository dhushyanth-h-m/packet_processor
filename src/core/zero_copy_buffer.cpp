#include "packet_processor/core/zero_copy_buffer.h"

namespace packet_processor {

ZeroCopyBuffer::ZeroCopyBuffer(uint32_t buffer_count, uint32_t buffer_size)
    : write_index_(0), read_index_(0) {
    // Allocate buffers
    buffers_.resize(buffer_count);
    
    // Initialize each buffer
    for (auto& buffer : buffers_) {
        buffer.data = new uint8_t[buffer_size];
        buffer.size = 0;
        buffer.capacity = buffer_size;
        buffer.in_use = false;
    }
}

ZeroCopyBuffer::~ZeroCopyBuffer() {
    // Free allocated memory
    for (auto& buffer : buffers_) {
        delete[] buffer.data;
    }
}

RingBufferEntry* ZeroCopyBuffer::getWriteBuffer() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Try to find an available buffer
    for (uint32_t i = 0; i < buffers_.size(); ++i) {
        // Get the next buffer index (round-robin)
        uint32_t index = (write_index_ + i) % buffers_.size();
        
        // Check if the buffer is available
        if (!buffers_[index].in_use) {
            // Mark buffer as in use
            buffers_[index].in_use = true;
            
            // Update write index
            write_index_ = (index + 1) % buffers_.size();
            
            // Reset buffer size
            buffers_[index].size = 0;
            
            return &buffers_[index];
        }
    }
    
    // No buffers available
    return nullptr;
}

void ZeroCopyBuffer::releaseWriteBuffer(uint32_t buffer_id) {
    if (buffer_id >= buffers_.size()) {
        return;
    }
    
    // Mark the buffer as available for reading
    // Note: We don't reset in_use here, as it's still in use (for reading)
    // The buffer will be fully released after reading
}

RingBufferEntry* ZeroCopyBuffer::getReadBuffer() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Try to find a buffer with data
    for (uint32_t i = 0; i < buffers_.size(); ++i) {
        // Get the next buffer index (round-robin)
        uint32_t index = (read_index_ + i) % buffers_.size();
        
        // Check if the buffer is in use and has data
        if (buffers_[index].in_use && buffers_[index].size > 0) {
            read_index_ = (index + 1) % buffers_.size();
            return &buffers_[index];
        }
    }
    
    // No buffers available for reading
    return nullptr;
}

void ZeroCopyBuffer::releaseReadBuffer(uint32_t buffer_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (buffer_id >= buffers_.size()) {
        return;
    }
    
    // Mark the buffer as fully released
    buffers_[buffer_id].in_use = false;
}

} // namespace packet_processor 