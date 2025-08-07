#include "ServerLogger.h"
#include <windows.h>
#include <fstream>
#include <iostream>
#include <ctime>
#include <iomanip>
#include <sstream>

static std::ofstream logFile;
static std::string logFilePath;

void ServerLogger::Initialize(const std::string& logFileName) {
    // Buat folder logs jika belum ada
    CreateDirectoryA("logs", NULL);

    // Buat path file log
    logFilePath = "logs\\" + logFileName;
    logFile.open(logFilePath, std::ios::app);

    if (logFile.is_open()) {
        Log(S_LOG_INFO, "=== Oblivion Eye Server Started ===");
    }
    else {
        std::cerr << "Warning: Could not open log file " << logFileName << " for writing." << std::endl;
    }
}

void ServerLogger::Log(ServerLogLevel level, const std::string& message) {
    if (logFile.is_open()) {
        WriteLog(level, message);
    }
    else {
        // Fallback ke console jika file log tidak bisa dibuka
        std::string levelStr = LogLevelToString(level);
        std::string timestamp = GetTimestamp();
        std::cout << "[" << timestamp << "] [" << levelStr << "] " << message << std::endl;
    }
}

void ServerLogger::WriteLog(ServerLogLevel level, const std::string& message) {
    std::string timestamp = GetTimestamp();
    std::string levelStr = LogLevelToString(level);

    logFile << "[" << timestamp << "] [" << levelStr << "] " << message << std::endl;
    logFile.flush(); // Pastikan data ditulis ke file

    // Untuk error dan validasi penting, tampilkan juga di console
    if (level == S_LOG_ERROR || level == S_LOG_VALIDATION) {
        std::cout << "[" << levelStr << "] " << message << std::endl;
    }
}

std::string ServerLogger::GetTimestamp() {
    time_t rawtime;
    struct tm timeinfo;

    time(&rawtime);
    localtime_s(&timeinfo, &rawtime);

    char buffer[80];
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &timeinfo);
    return std::string(buffer);
}

std::string ServerLogger::LogLevelToString(ServerLogLevel level) {
    switch (level) {
    case S_LOG_INFO: return "INFO";
    case S_LOG_WARNING: return "WARNING";
    case S_LOG_ERROR: return "ERROR";
    case S_LOG_CLIENT_CONN: return "CLIENT_CONN";
    case S_LOG_CLIENT_DATA: return "CLIENT_DATA";
    case S_LOG_VALIDATION: return "VALIDATION";
    default: return "UNKNOWN";
    }
}

void ServerLogger::Close() {
    if (logFile.is_open()) {
        Log(S_LOG_INFO, "=== Oblivion Eye Server Stopped ===");
        logFile.close();
    }
}