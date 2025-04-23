#pragma once

#include <string>
#include <fstream>
#include <mutex>
#include <memory>
#include <vector>
#include <functional>

namespace packet_processor {

/**
 * @brief Log level
 */
enum class LogLevel {
    DEBUG,
    INFO,
    WARNING,
    ERROR
};

/**
 * @brief Logger class for packet processor
 * 
 * This class provides a thread-safe logging facility for the packet processor.
 * It supports multiple output destinations (console, file) and different log levels.
 */
class Logger {
public:
    /**
     * @brief Construct a new Logger
     * 
     * @param level Minimum log level to record
     * @param console_output Whether to output to console
     * @param file_output Whether to output to file
     * @param file_path File path for log file (if file_output is true)
     */
    Logger(LogLevel level = LogLevel::INFO, 
          bool console_output = true, 
          bool file_output = false,
          const std::string& file_path = "packet_processor.log");
    
    /**
     * @brief Destructor
     */
    ~Logger();
    
    /**
     * @brief Log a message
     * 
     * @param level Log level
     * @param message Log message
     */
    void log(LogLevel level, const std::string& message);
    
    /**
     * @brief Log a debug message
     * 
     * @param message Log message
     */
    void debug(const std::string& message);
    
    /**
     * @brief Log an info message
     * 
     * @param message Log message
     */
    void info(const std::string& message);
    
    /**
     * @brief Log a warning message
     * 
     * @param message Log message
     */
    void warning(const std::string& message);
    
    /**
     * @brief Log an error message
     * 
     * @param message Log message
     */
    void error(const std::string& message);
    
    /**
     * @brief Set the log level
     * 
     * @param level New log level
     */
    void setLevel(LogLevel level);
    
    /**
     * @brief Get the current log level
     * 
     * @return Current log level
     */
    LogLevel getLevel() const;
    
    /**
     * @brief Enable or disable console output
     * 
     * @param enable Whether to enable console output
     */
    void enableConsoleOutput(bool enable);
    
    /**
     * @brief Enable or disable file output
     * 
     * @param enable Whether to enable file output
     * @param file_path File path for log file
     */
    void enableFileOutput(bool enable, const std::string& file_path = "");
    
    /**
     * @brief Add a custom log handler
     * 
     * @param handler Function to call with log messages
     * @return Handler ID for removing the handler later
     */
    int addLogHandler(std::function<void(LogLevel, const std::string&)> handler);
    
    /**
     * @brief Remove a custom log handler
     * 
     * @param handler_id Handler ID returned by addLogHandler
     * @return true if the handler was removed
     */
    bool removeLogHandler(int handler_id);
    
    /**
     * @brief Convert LogLevel to string
     * 
     * @param level Log level
     * @return String representation of log level
     */
    static std::string levelToString(LogLevel level);
    
    /**
     * @brief Convert string to LogLevel
     * 
     * @param level String representation of log level
     * @return LogLevel
     */
    static LogLevel stringToLevel(const std::string& level);
    
private:
    LogLevel level_;
    bool console_output_;
    bool file_output_;
    std::string file_path_;
    std::ofstream file_stream_;
    
    mutable std::mutex mutex_;
    
    struct LogHandler {
        int id;
        std::function<void(LogLevel, const std::string&)> handler;
    };
    
    std::vector<LogHandler> handlers_;
    int next_handler_id_;
    
    /**
     * @brief Write a log message to all enabled outputs
     * 
     * @param level Log level
     * @param message Log message
     */
    void writeLog(LogLevel level, const std::string& message);
    
    /**
     * @brief Get a formatted timestamp
     * 
     * @return Formatted timestamp string
     */
    std::string getTimestamp() const;
};

} // namespace packet_processor 