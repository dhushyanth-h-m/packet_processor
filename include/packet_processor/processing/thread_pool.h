#pragma once

#include <vector>
#include <queue>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <functional>
#include <future>
#include <atomic>
#include <memory>

namespace packet_processor {

/**
 * @brief Thread pool for multi-threaded packet processing
 * 
 * This class implements a thread pool optimized for packet processing with
 * features specific to macOS. It supports assigning real-time priority to threads,
 * handles thermal throttling, and is optimized for both Intel and Apple Silicon.
 */
class ThreadPool {
public:
    /**
     * @brief Construct a new Thread Pool
     * 
     * @param num_threads Number of threads to create (0 = auto-detect)
     * @param use_realtime Whether to use real-time priority for threads
     */
    ThreadPool(unsigned int num_threads = 0, bool use_realtime = false);
    
    /**
     * @brief Destructor
     */
    ~ThreadPool();
    
    /**
     * @brief Initialize the thread pool
     * 
     * @return true if initialization was successful
     */
    bool initialize();
    
    /**
     * @brief Start the thread pool
     */
    void start();
    
    /**
     * @brief Stop the thread pool
     */
    void stop();
    
    /**
     * @brief Submit a task to the thread pool
     * 
     * @param f Function to execute
     * @param args Arguments to pass to the function
     * @return std::future<return type of f>
     */
    template<class F, class... Args>
    auto submit(F&& f, Args&&... args) -> std::future<typename std::result_of<F(Args...)>::type>;
    
    /**
     * @brief Submit a batch of tasks to the thread pool
     * 
     * @param tasks Vector of functions to execute
     */
    void submitBatch(const std::vector<std::function<void()>>& tasks);
    
    /**
     * @brief Get the number of threads in the pool
     * 
     * @return Number of threads
     */
    unsigned int getThreadCount() const { return num_threads_; }
    
    /**
     * @brief Get the CPU usage for each thread
     * 
     * @return Vector of CPU usage percentages
     */
    std::vector<double> getThreadCpuUsage() const;
    
    /**
     * @brief Get the total CPU usage for all threads
     * 
     * @return Total CPU usage percentage
     */
    double getTotalCpuUsage() const;
    
private:
    unsigned int num_threads_;                 ///< Number of threads
    bool use_realtime_;                       ///< Whether to use real-time priority
    
    std::vector<std::thread> threads_;        ///< Worker threads
    std::vector<std::thread::id> thread_ids_; ///< Thread IDs
    
    std::queue<std::function<void()>> tasks_; ///< Task queue
    std::mutex queue_mutex_;                  ///< Mutex for task queue
    std::condition_variable cv_;              ///< Condition variable for task signaling
    
    std::atomic<bool> running_;               ///< Whether the thread pool is running
    std::atomic<bool> stop_requested_;        ///< Whether stop has been requested
    
    /**
     * @brief Worker thread function
     * 
     * @param thread_id ID of this thread
     */
    void workerFunction(unsigned int thread_id);
    
    /**
     * @brief Set real-time priority for the current thread
     * 
     * @return true if priority was set successfully
     */
    bool setRealtimePriority();
    
    /**
     * @brief Detect optimal number of threads for packet processing
     * 
     * @return Optimal number of threads
     */
    static unsigned int detectOptimalThreadCount();
    
    /**
     * @brief Get thread-specific CPU usage on macOS
     * 
     * @param thread_id Thread ID
     * @return CPU usage percentage for the thread
     */
    double getThreadCpuUsage(std::thread::id thread_id) const;
};

// Template implementation
template<class F, class... Args>
auto ThreadPool::submit(F&& f, Args&&... args) -> std::future<typename std::result_of<F(Args...)>::type> {
    using return_type = typename std::result_of<F(Args...)>::type;
    
    // Create a shared_ptr to a packaged_task with the required type
    auto task = std::make_shared<std::packaged_task<return_type()>>(
        std::bind(std::forward<F>(f), std::forward<Args>(args)...)
    );
    
    // Get the future from the task before moving the task into the queue
    std::future<return_type> result = task->get_future();
    
    {
        std::unique_lock<std::mutex> lock(queue_mutex_);
        
        // Don't allow adding tasks after the thread pool has been stopped
        if (stop_requested_) {
            throw std::runtime_error("Cannot submit task to stopped thread pool");
        }
        
        // Add the task to the queue
        tasks_.emplace([task]() { (*task)(); });
    }
    
    // Notify one thread that a task is available
    cv_.notify_one();
    
    return result;
}

} // namespace packet_processor 