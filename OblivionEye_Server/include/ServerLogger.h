#ifndef SERVER_LOGGER_H
#define SERVER_LOGGER_H

#include <string>
#include <mutex>

// Use typedef to avoid Windows macro conflicts
typedef enum {
    LOG_DEBUG = 0,
    LOG_INFO = 1,
    LOG_WARNING = 2,
    LOG_ERROR = 3,
    LOG_SECURITY = 4
} LogLevel;

struct LoggerConfig {
    std::string logFilePath;
    LogLevel minLogLevel;
    size_t maxFileSizeMB;
    int maxBackupFiles;
    bool enableConsoleOutput;

    LoggerConfig();
};

class ServerLogger {
private:
    mutable std::mutex log_mutex;
    std::string logFilePath;
    LogLevel currentLogLevel;
    size_t maxFileSize;
    int maxFiles;
    bool enableConsole;

    std::string getCurrentTimestamp() const;
    std::string levelToString(LogLevel level) const;
    bool shouldRotate() const;
    void rotateLogs();
    void createLogDirectory() const;

public:
    ServerLogger();
    ~ServerLogger();

    void configure(const LoggerConfig& config);
    void log(LogLevel level, const std::string& message);
    void logWithClientInfo(LogLevel level, const std::string& clientIP, const std::string& message);

    void logDebug(const std::string& message);
    void logInfo(const std::string& message);
    void logWarning(const std::string& message);
    void logError(const std::string& message);
    void logSecurity(const std::string& message);

    void logClientConnection(const std::string& clientIP, int clientPort);
    void logClientDisconnection(const std::string& clientIP, int clientPort);
    void logClientHWIDCheck(const std::string& clientIP, const std::string& hwid, bool allowed);
    void logClientSecurityAlert(const std::string& clientIP, const std::string& alertType, const std::string& details);

    std::string getLogFilePath() const;
    LogLevel getCurrentLogLevel() const;
};

#endif // SERVER_LOGGER_H