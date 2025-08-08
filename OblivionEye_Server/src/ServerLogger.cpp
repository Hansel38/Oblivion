#include "ServerLogger.h"
#include <iostream>
#include <fstream>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <filesystem>
#include <algorithm>

LoggerConfig::LoggerConfig() {
    logFilePath = "logs/server.log";
    minLogLevel = LOG_INFO;
    maxFileSizeMB = 10;
    maxBackupFiles = 5;
    enableConsoleOutput = true;
}

ServerLogger::ServerLogger() {
    logFilePath = "logs/server.log";
    currentLogLevel = LOG_INFO;
    maxFileSize = 10 * 1024 * 1024;
    maxFiles = 5;
    enableConsole = true;

    createLogDirectory();
}

ServerLogger::~ServerLogger() {
}

std::string ServerLogger::getLogFilePath() const {
    return logFilePath;
}

LogLevel ServerLogger::getCurrentLogLevel() const {
    return currentLogLevel;
}

void ServerLogger::configure(const LoggerConfig& config) {
    std::lock_guard<std::mutex> lock(log_mutex);

    logFilePath = config.logFilePath;
    currentLogLevel = config.minLogLevel;
    maxFileSize = config.maxFileSizeMB * 1024 * 1024;
    maxFiles = config.maxBackupFiles;
    enableConsole = config.enableConsoleOutput;

    createLogDirectory();
}

std::string ServerLogger::getCurrentTimestamp() const {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;

    std::tm local_tm;
#ifdef _WIN32
    localtime_s(&local_tm, &time_t);
#else
    localtime_r(&time_t, &local_tm);
#endif

    std::stringstream ss;
    ss << std::put_time(&local_tm, "%Y-%m-%d %H:%M:%S");
    ss << '.' << std::setfill('0') << std::setw(3) << ms.count();
    return ss.str();
}

std::string ServerLogger::levelToString(LogLevel level) const {
    switch (level) {
    case LOG_DEBUG:    return "DEBUG";
    case LOG_INFO:     return "INFO";
    case LOG_WARNING:  return "WARN";
    case LOG_ERROR:    return "ERROR";
    case LOG_SECURITY: return "SECURITY";
    default:           return "UNKNOWN";
    }
}

void ServerLogger::createLogDirectory() const {
    try {
        std::filesystem::path logPath(logFilePath);
        std::filesystem::create_directories(logPath.parent_path());
    }
    catch (const std::exception& e) {
        std::cerr << "Warning: Could not create log directory: " << e.what() << std::endl;
    }
}

bool ServerLogger::shouldRotate() const {
    std::ifstream file(logFilePath, std::ios::binary | std::ios::ate);
    if (file.is_open()) {
        std::streamsize size = file.tellg();
        return size >= static_cast<std::streamsize>(maxFileSize);
    }
    return false;
}

void ServerLogger::rotateLogs() {
    for (int i = maxFiles - 1; i > 0; i--) {
        std::string oldName = logFilePath + "." + std::to_string(i);
        std::string newName = logFilePath + "." + std::to_string(i + 1);

        if (std::filesystem::exists(oldName)) {
            std::filesystem::rename(oldName, newName);
        }
    }

    if (std::filesystem::exists(logFilePath)) {
        std::string newName = logFilePath + ".1";
        std::filesystem::rename(logFilePath, newName);
    }
}

void ServerLogger::log(LogLevel level, const std::string& message) {
    if (level < currentLogLevel) {
        return;
    }

    std::lock_guard<std::mutex> lock(log_mutex);

    if (shouldRotate()) {
        rotateLogs();
    }

    std::string timestamp = getCurrentTimestamp();
    std::string levelStr = levelToString(level);

    std::string logMessage = "[" + timestamp + "] [" + levelStr + "] " + message;

    std::ofstream logFile(logFilePath, std::ios::app);
    if (logFile.is_open()) {
        logFile << logMessage << std::endl;
        logFile.close();
    }

    if (enableConsole) {
        switch (level) {
        case LOG_ERROR:
        case LOG_SECURITY:
            std::cerr << logMessage << std::endl;
            break;
        default:
            std::cout << logMessage << std::endl;
            break;
        }
    }
}

void ServerLogger::logWithClientInfo(LogLevel level, const std::string& clientIP, const std::string& message) {
    std::string formattedMessage = "[Client: " + clientIP + "] " + message;
    log(level, formattedMessage);
}

void ServerLogger::logDebug(const std::string& message) {
    log(LOG_DEBUG, message);
}

void ServerLogger::logInfo(const std::string& message) {
    log(LOG_INFO, message);
}

void ServerLogger::logWarning(const std::string& message) {
    log(LOG_WARNING, message);
}

void ServerLogger::logError(const std::string& message) {
    log(LOG_ERROR, message);
}

void ServerLogger::logSecurity(const std::string& message) {
    log(LOG_SECURITY, message);
}

void ServerLogger::logClientConnection(const std::string& clientIP, int clientPort) {
    std::string message = "Client connected from " + clientIP + ":" + std::to_string(clientPort);
    logInfo(message);
}

void ServerLogger::logClientDisconnection(const std::string& clientIP, int clientPort) {
    std::string message = "Client disconnected from " + clientIP + ":" + std::to_string(clientPort);
    logInfo(message);
}

void ServerLogger::logClientHWIDCheck(const std::string& clientIP, const std::string& hwid, bool allowed) {
    std::string status = allowed ? "ALLOWED" : "DENIED";
    std::string message = "HWID check for " + hwid + " from " + clientIP + ": " + status;
    LogLevel level = allowed ? LOG_INFO : LOG_SECURITY;
    log(level, message);
}

void ServerLogger::logClientSecurityAlert(const std::string& clientIP, const std::string& alertType, const std::string& details) {
    std::string message = "SECURITY ALERT [" + alertType + "] from " + clientIP + ": " + details;
    logSecurity(message);
}