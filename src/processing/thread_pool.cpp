#include "packet_processor/processing/thread_pool.h"
#include <thread>
#include <functional>
#include <iostream>
#include <cmath>
#include <algorithm>
#include <pthread.h>

#ifdef __APPLE__
#include <mach/mach.h>
#include <mach/thread_policy.h>
#include <mach/thread_act.h>
#include <sys/resource.h>
#include <sys/sysctl.h>
#endif

namespace packet_processor {

ThreadPool::ThreadPool(unsigned int num_threads, bool use_realtime)
    : num_threads_(num_threads),
      use_realtime_(use_realtime),
      running_(false),
      stop_requested_(false) {
    
    // Auto-detect optimal thread count if not specified
    if (num_threads_ == 0) {
        num_threads_ = detectOptimalThreadCount();
    }
}

ThreadPool::~ThreadPool() {
    stop();
}

bool ThreadPool::initialize() {
    // No special initialization needed
    return true;
}

void ThreadPool::start() {
    if (running_) {
        return;
    }
    
    // Reset stop flag
    stop_requested_ = false;
    running_ = true;
    
    // Create worker threads
    threads_.resize(num_threads_);
    thread_ids_.resize(num_threads_);
    
    for (unsigned int i = 0; i < num_threads_; ++i) {
        threads_[i] = std::thread(&ThreadPool::workerFunction, this, i);
        thread_ids_[i] = threads_[i].get_id();
    }
}

void ThreadPool::stop() {
    if (!running_) {
        return;
    }
    
    // Set stop flag
    stop_requested_ = true;
    
    // Wake up all threads to check the stop flag
    {
        std::unique_lock<std::mutex> lock(queue_mutex_);
        cv_.notify_all();
    }
    
    // Wait for all threads to finish
    for (auto& thread : threads_) {
        if (thread.joinable()) {
            thread.join();
        }
    }
    
    // Clear threads
    threads_.clear();
    thread_ids_.clear();
    
    // Clear any remaining tasks
    {
        std::unique_lock<std::mutex> lock(queue_mutex_);
        while (!tasks_.empty()) {
            tasks_.pop();
        }
    }
    
    running_ = false;
}

void ThreadPool::submitBatch(const std::vector<std::function<void()>>& tasks) {
    if (stop_requested_) {
        throw std::runtime_error("Cannot submit tasks to stopped thread pool");
    }
    
    // Add all tasks to the queue
    {
        std::unique_lock<std::mutex> lock(queue_mutex_);
        for (const auto& task : tasks) {
            tasks_.push(task);
        }
    }
    
    // Notify workers that tasks are available
    // Wake up as many threads as there are tasks
    for (size_t i = 0; i < std::min(tasks.size(), thread_ids_.size()); ++i) {
        cv_.notify_one();
    }
}

void ThreadPool::workerFunction(unsigned int thread_id) {
    // Set thread name for debugging
    #if defined(__APPLE__) && defined(__MACH__)
    pthread_setname_np(("Worker-" + std::to_string(thread_id)).c_str());
    #endif
    
    // Set real-time priority if requested
    if (use_realtime_) {
        setRealtimePriority();
    }
    
    while (true) {
        std::function<void()> task;
        
        // Get a task from the queue
        {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            
            // Wait for a task or stop signal
            cv_.wait(lock, [this]() {
                return stop_requested_ || !tasks_.empty();
            });
            
            // Check if we should stop
            if (stop_requested_ && tasks_.empty()) {
                break;
            }
            
            // Get the next task
            if (!tasks_.empty()) {
                task = std::move(tasks_.front());
                tasks_.pop();
            }
        }
        
        // Execute the task
        if (task) {
            task();
        }
    }
}

bool ThreadPool::setRealtimePriority() {
#ifdef __APPLE__
    // On macOS, we use the Mach API to set thread priority
    
    // Get the thread port
    mach_port_t thread_port = pthread_mach_thread_np(pthread_self());
    
    // Set thread policy
    thread_extended_policy_data_t extended_policy;
    extended_policy.timeshare = 0; // Set to non-timeshare (real-time) mode
    
    kern_return_t result = thread_policy_set(
        thread_port,
        THREAD_EXTENDED_POLICY,
        (thread_policy_t)&extended_policy,
        THREAD_EXTENDED_POLICY_COUNT
    );
    
    if (result != KERN_SUCCESS) {
        std::cerr << "Failed to set thread extended policy: " << result << std::endl;
        return false;
    }
    
    // Set thread priority
    thread_precedence_policy_data_t precedence_policy;
    precedence_policy.importance = 63; // Max priority (0-63)
    
    result = thread_policy_set(
        thread_port,
        THREAD_PRECEDENCE_POLICY,
        (thread_policy_t)&precedence_policy,
        THREAD_PRECEDENCE_POLICY_COUNT
    );
    
    if (result != KERN_SUCCESS) {
        std::cerr << "Failed to set thread precedence policy: " << result << std::endl;
        return false;
    }
    
    // Set thread real-time constraints
    thread_time_constraint_policy_data_t time_constraint_policy;
    time_constraint_policy.period = 0;       // No fixed period
    time_constraint_policy.computation = 50000;  // 50ms of computation per 100ms
    time_constraint_policy.constraint = 100000;  // Deadline is 100ms
    time_constraint_policy.preemptible = 1;      // Allow thread to be preempted
    
    result = thread_policy_set(
        thread_port,
        THREAD_TIME_CONSTRAINT_POLICY,
        (thread_policy_t)&time_constraint_policy,
        THREAD_TIME_CONSTRAINT_POLICY_COUNT
    );
    
    if (result != KERN_SUCCESS) {
        std::cerr << "Failed to set thread time constraint policy: " << result << std::endl;
        return false;
    }
    
    return true;
#else
    // Not implemented for other platforms
    return false;
#endif
}

unsigned int ThreadPool::detectOptimalThreadCount() {
    // Start with the number of hardware threads
    unsigned int hwThreads = std::thread::hardware_concurrency();
    
    // On Apple Silicon, we can optimize based on the core types
#ifdef __APPLE__
    if (isAppleSilicon()) {
        // Check if we can get the number of performance cores
        int performanceCores = 0;
        size_t size = sizeof(performanceCores);
        
        // Try to get the number of performance cores
        if (sysctlbyname("hw.perflevel0.physicalcpu", &performanceCores, &size, nullptr, 0) == 0) {
            // Use performance cores + 1 efficiency core for best throughput
            return performanceCores + 1;
        }
    }
#endif
    
    // If we can't determine the optimal count based on core types,
    // use a heuristic approach:
    // - For systems with <= 4 cores: use all cores
    // - For systems with > 4 cores: use 75% of cores (rounded up)
    // This leaves some CPU for the OS and other processes
    if (hwThreads <= 4) {
        return hwThreads;
    } else {
        return static_cast<unsigned int>(std::ceil(hwThreads * 0.75));
    }
}

bool isAppleSilicon() {
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

std::vector<double> ThreadPool::getThreadCpuUsage() const {
    std::vector<double> result(num_threads_, 0.0);
    
    for (size_t i = 0; i < num_threads_; ++i) {
        if (i < thread_ids_.size()) {
            result[i] = getThreadCpuUsage(thread_ids_[i]);
        }
    }
    
    return result;
}

double ThreadPool::getTotalCpuUsage() const {
    std::vector<double> thread_usage = getThreadCpuUsage();
    
    // Sum up all thread usages
    return std::accumulate(thread_usage.begin(), thread_usage.end(), 0.0);
}

double ThreadPool::getThreadCpuUsage(std::thread::id thread_id) const {
#ifdef __APPLE__
    // On macOS, we can use the Mach API to get thread CPU usage
    
    // Convert std::thread::id to pthread_t
    pthread_t pthread_id = 0;
    for (size_t i = 0; i < thread_ids_.size(); ++i) {
        if (thread_ids_[i] == thread_id) {
            pthread_id = threads_[i].native_handle();
            break;
        }
    }
    
    if (pthread_id == 0) {
        return 0.0;
    }
    
    // Get the mach thread port
    mach_port_t thread_port = pthread_mach_thread_np(pthread_id);
    
    // Get thread basic info
    thread_basic_info_data_t info;
    mach_msg_type_number_t count = THREAD_BASIC_INFO_COUNT;
    
    kern_return_t result = thread_info(
        thread_port,
        THREAD_BASIC_INFO,
        (thread_info_t)&info,
        &count
    );
    
    if (result != KERN_SUCCESS) {
        return 0.0;
    }
    
    // Calculate CPU usage
    double usage = 0.0;
    if (info.flags & TH_FLAGS_IDLE) {
        usage = 0.0;
    } else {
        usage = (info.cpu_usage / (float)TH_USAGE_SCALE) * 100.0;
    }
    
    return usage;
#else
    // Not implemented for other platforms
    return 0.0;
#endif
}

} // namespace packet_processor 