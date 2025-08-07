#include "../include/Logger.h"
#include <windows.h>
#include <fstream>
#include <iostream>
#include <ctime>
#include <iomanip>
#include <sstream>

static std::ofstream logFile;
static std::string logFilePath;

void Logger::Initialize(const std::string& logFileName) {
    // Buat folder logs jika belum ada
    CreateDirectoryA("logs", NULL);

    // Buat path file log
    logFilePath = "logs\\" + logFileName;
    logFile.open(logFilePath, std::ios::app);

    if (logFile.is_open()) {
        Log(LOG_INFO, "=== Oblivion Eye Started ===");
    }
}

void Logger::Log(LogLevel level, const std::string& message) {
    if (logFile.is_open()) {
        WriteLog(level, message);
    }
}

void Logger::WriteLog(LogLevel level, const std::string& message) {
    std::string timestamp = GetTimestamp();
    std::string levelStr = LogLevelToString(level);

    logFile << "[" << timestamp << "] [" << levelStr << "] " << message << std::endl;
    logFile.flush();

    if (level == LOG_DETECTED) {
        OutputDebugStringA(("[OblivionEye] " + message + "\n").c_str());
    }
}

std::string Logger::GetTimestamp() {
    time_t rawtime;
    struct tm timeinfo;

    time(&rawtime);
    localtime_s(&timeinfo, &rawtime);

    char buffer[80];
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &timeinfo);
    return std::string(buffer);
}

std::string Logger::LogLevelToString(LogLevel level) {
    switch (level) {
    case LOG_INFO: return "INFO";
    case LOG_WARNING: return "WARNING";
    case LOG_ERROR: return "ERROR";
    case LOG_DETECTED: return "DETECTED";
    default: return "UNKNOWN";
    }
}

void Logger::Close() {
    if (logFile.is_open()) {
        Log(LOG_INFO, "=== Oblivion Eye Stopped ===");
        logFile.close();
    }
}