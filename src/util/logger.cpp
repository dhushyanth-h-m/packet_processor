#include "packet_processor/util/logger.h"
#include <iostream>
#include <iomanip>
#include <chrono>
#include <ctime>
#include <sstream>

namespace packet_processor {

Logger::Logger(LogLevel level, bool console_output, bool file_output, const std::string& file_path)
    : level_(level),
      console_output_(console_output),
      file_output_(file_output),
      file_path_(file_path),
      next_handler_id_(0) {
    
    // Open log file if needed
    if (file_output_) {
        file_stream_.open(file_path_, std::ios::out | std::ios::app);
        if (!file_stream_.is_open()) {
            std::cerr << "Failed to open log file: " << file_path_ << std::endl;
            file_output_ = false;
        }
    }
}

Logger::~Logger() {
    // Close log file
    if (file_stream_.is_open()) {
        file_stream_.close();
    }
}

void Logger::log(LogLevel level, const std::string& message) {
    // Check if we should log this message
    if (level < level_) {
        return;
    }
    
    // Write log message
    writeLog(level, message);
}

void Logger::debug(const std::string& message) {
    log(LogLevel::DEBUG, message);
}

void Logger::info(const std::string& message) {
    log(LogLevel::INFO, message);
}

void Logger::warning(const std::string& message) {
    log(LogLevel::WARNING, message);
}

void Logger::error(const std::string& message) {
    log(LogLevel::ERROR, message);
}

void Logger::setLevel(LogLevel level) {
    std::lock_guard<std::mutex> lock(mutex_);
    level_ = level;
}

LogLevel Logger::getLevel() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return level_;
}

void Logger::enableConsoleOutput(bool enable) {
    std::lock_guard<std::mutex> lock(mutex_);
    console_output_ = enable;
}

void Logger::enableFileOutput(bool enable, const std::string& file_path) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Close existing file if open
    if (file_stream_.is_open()) {
        file_stream_.close();
    }
    
    // Update file output settings
    file_output_ = enable;
    
    if (!file_path.empty()) {
        file_path_ = file_path;
    }
    
    // Open new file if needed
    if (file_output_) {
        file_stream_.open(file_path_, std::ios::out | std::ios::app);
        if (!file_stream_.is_open()) {
            std::cerr << "Failed to open log file: " << file_path_ << std::endl;
            file_output_ = false;
        }
    }
}

int Logger::addLogHandler(std::function<void(LogLevel, const std::string&)> handler) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    int id = next_handler_id_++;
    handlers_.push_back({id, handler});
    
    return id;
}

bool Logger::removeLogHandler(int handler_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    for (auto it = handlers_.begin(); it != handlers_.end(); ++it) {
        if (it->id == handler_id) {
            handlers_.erase(it);
            return true;
        }
    }
    
    return false;
}

std::string Logger::levelToString(LogLevel level) {
    switch (level) {
        case LogLevel::DEBUG:
            return "DEBUG";
        case LogLevel::INFO:
            return "INFO";
        case LogLevel::WARNING:
            return "WARNING";
        case LogLevel::ERROR:
            return "ERROR";
        default:
            return "UNKNOWN";
    }
}

LogLevel Logger::stringToLevel(const std::string& level) {
    if (level == "debug") {
        return LogLevel::DEBUG;
    } else if (level == "info") {
        return LogLevel::INFO;
    } else if (level == "warning") {
        return LogLevel::WARNING;
    } else if (level == "error") {
        return LogLevel::ERROR;
    } else {
        return LogLevel::INFO;  // Default to INFO
    }
}

void Logger::writeLog(LogLevel level, const std::string& message) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Format log message
    std::ostringstream log_message;
    log_message << getTimestamp() << " [" << levelToString(level) << "] " << message;
    
    // Write to console
    if (console_output_) {
        // Set color based on log level
        switch (level) {
            case LogLevel::DEBUG:
                std::cout << "\033[37m";  // White
                break;
            case LogLevel::INFO:
                std::cout << "\033[32m";  // Green
                break;
            case LogLevel::WARNING:
                std::cout << "\033[33m";  // Yellow
                break;
            case LogLevel::ERROR:
                std::cout << "\033[31m";  // Red
                break;
            default:
                break;
        }
        
        // Print log message
        std::cout << log_message.str() << "\033[0m" << std::endl;
    }
    
    // Write to file
    if (file_output_ && file_stream_.is_open()) {
        file_stream_ << log_message.str() << std::endl;
        file_stream_.flush();
    }
    
    // Call custom handlers
    for (const auto& handler : handlers_) {
        handler.handler(level, message);
    }
}

std::string Logger::getTimestamp() const {
    auto now = std::chrono::system_clock::now();
    auto now_time_t = std::chrono::system_clock::to_time_t(now);
    auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;
    
    std::ostringstream timestamp;
    timestamp << std::put_time(std::localtime(&now_time_t), "%Y-%m-%d %H:%M:%S");
    timestamp << '.' << std::setfill('0') << std::setw(3) << now_ms.count();
    
    return timestamp.str();
}

} // namespace packet_processor 