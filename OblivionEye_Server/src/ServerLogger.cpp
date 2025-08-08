#include "ServerLogger.h"
#include <iostream>
#include <fstream>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <filesystem>
#include <algorithm>

// Disable deprecation warnings for this file
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4996)
#endif

ServerLogger::ServerLogger()
    : logFilePath("logs/server.log")
    , currentLogLevel(INFO)
    , maxFileSize(10 * 1024 * 1024) // 10 MB
    , maxFiles(5)
    , enableConsole(true) {

    createLogDirectory();
}

ServerLogger::~ServerLogger() {
    // Logger destructor
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

    // Safe localtime usage
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
    case DEBUG:    return "DEBUG";
    case INFO:     return "INFO";
    case WARNING:  return "WARN";
    case ERROR:    return "ERROR";
    case SECURITY: return "SECURITY";
    default:       return "UNKNOWN";
    }
}

void ServerLogger::createLogDirectory() const {
    try {
        std::filesystem::path logPath(logFilePath);
        std::filesystem::create_directories(logPath.parent_path());
    }
    catch (const std::exception& e) {
        // Jika gagal membuat direktori, tetap lanjut
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
    // Tutup file yang sedang aktif
    // Rename file log saat ini
    for (int i = maxFiles - 1; i > 0; i--) {
        std::string oldName = logFilePath + "." + std::to_string(i);
        std::string newName = logFilePath + "." + std::to_string(i + 1);

        if (std::filesystem::exists(oldName)) {
            std::filesystem::rename(oldName, newName);
        }
    }

    // Rename file log utama
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

    // Cek apakah perlu rotasi
    if (shouldRotate()) {
        rotateLogs();
    }

    std::string timestamp = getCurrentTimestamp();
    std::string levelStr = levelToString(level);

    std::string logMessage = "[" + timestamp + "] [" + levelStr + "] " + message;

    // Tulis ke file
    std::ofstream logFile(logFilePath, std::ios::app);
    if (logFile.is_open()) {
        logFile << logMessage << std::endl;
        logFile.close();
    }

    // Output ke console jika diaktifkan
    if (enableConsole) {
        switch (level) {
        case ERROR:
        case SECURITY:
            std::cerr << logMessage << std::endl;
            break;
        default:
            std::cout << logMessage << std::endl;
            break;
        }
    }
}

void ServerLogger::logWithClientInfo(LogLevel level, const std::string& clientInfo,
    const std::string& message) {
    std::string formattedMessage = "[Client: " + clientInfo + "] " + message;
    log(level, formattedMessage);
}

// Convenience methods
void ServerLogger::logDebug(const std::string& message) {
    log(DEBUG, message);
}

void ServerLogger::logInfo(const std::string& message) {
    log(INFO, message);
}

void ServerLogger::logWarning(const std::string& message) {
    log(WARNING, message);
}

void ServerLogger::logError(const std::string& message) {
    log(ERROR, message);
}

void ServerLogger::logSecurity(const std::string& message) {
    log(SECURITY, message);
}

// Client-specific logging methods
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
    LogLevel level = allowed ? INFO : SECURITY;
    log(level, message);
}

void ServerLogger::logClientSecurityAlert(const std::string& clientIP, const std::string& alertType,
    const std::string& details) {
    std::string message = "SECURITY ALERT [" + alertType + "] from " + clientIP + ": " + details;
    logSecurity(message);
}

#ifdef _MSC_VER
#pragma warning(pop)
#endif