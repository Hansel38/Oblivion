#ifndef SERVER_LOGGER_H
#define SERVER_LOGGER_H

#include <string>
#include <mutex>
#include <fstream>

enum LogLevel {
    DEBUG = 0,
    INFO = 1,
    WARNING = 2,
    ERROR = 3,
    SECURITY = 4
};

struct LoggerConfig {
    std::string logFilePath = "logs/server.log";
    LogLevel minLogLevel = INFO;
    size_t maxFileSizeMB = 10;
    int maxBackupFiles = 5;
    bool enableConsoleOutput = true;
};

class ServerLogger {
private:
    mutable std::mutex log_mutex;
    std::string logFilePath;
    LogLevel currentLogLevel;
    size_t maxFileSize;
    int maxFiles;
    bool enableConsole;

    // Helper methods
    std::string getCurrentTimestamp() const;
    std::string levelToString(LogLevel level) const;
    bool shouldRotate() const;
    void rotateLogs();
    void createLogDirectory() const;

public:
    ServerLogger();
    ~ServerLogger();

    // Configuration
    void configure(const LoggerConfig& config);

    // Main logging methods
    void log(LogLevel level, const std::string& message);
    void logWithClientInfo(LogLevel level, const std::string& clientInfo,
        const std::string& message);

    // Convenience methods
    void logDebug(const std::string& message);
    void logInfo(const std::string& message);
    void logWarning(const std::string& message);
    void logError(const std::string& message);
    void logSecurity(const std::string& message);

    // Client-specific logging
    void logClientConnection(const std::string& clientIP, int clientPort);
    void logClientDisconnection(const std::string& clientIP, int clientPort);
    void logClientHWIDCheck(const std::string& clientIP, const std::string& hwid, bool allowed);
    void logClientSecurityAlert(const std::string& clientIP, const std::string& alertType,
        const std::string& details);

    // Utility methods
    std::string getLogFilePath() const { return logFilePath; }
    LogLevel getCurrentLogLevel() const { return currentLogLevel; }
};

#endif // SERVER_LOGGER_H