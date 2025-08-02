#include "../include/Logger.h"
#include <fstream>
#include <windows.h>
#include <shlwapi.h>
#include <ctime>
#include <iomanip>
#include <sstream>
#pragma comment(lib, "shlwapi.lib")

static std::ofstream logFile;
static std::string logPath;

static std::string getCurrentTime() {
    time_t now = time(0);
    struct tm timeinfo;
    localtime_s(&timeinfo, &now);

    std::ostringstream oss;
    oss << std::put_time(&timeinfo, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

void Logger::Init() {
    // Opsional: log startup jika diperlukan
    // Untuk saat ini kita tidak log startup
}

void Logger::Log(const std::string& message) {
    // Hanya log event penting spesifik
    // Untuk pesan umum, kita tidak log kecuali diperlukan
}

void Logger::LogDetected(const std::string& processName) {
    // Buka file log hanya saat dibutuhkan
    if (!logFile.is_open()) {
        char dllPath[MAX_PATH];
        GetModuleFileNameA(NULL, dllPath, MAX_PATH);
        PathRemoveFileSpecA(dllPath);
        logPath = std::string(dllPath) + "\\oblivion_log.txt";
        logFile.open(logPath, std::ios::app);

        if (logFile.is_open()) {
            logFile << "\n=== OBLIVION EYE SESSION ===\n";
        }
    }

    if (logFile.is_open()) {
        std::string timestamp = getCurrentTime();
        logFile << "[" << timestamp << "] CHEAT DETECTED: " << processName << "\n";
        logFile.flush();
    }
}

void Logger::Close() {
    // Hanya log shutdown jika file sudah dibuka (ada deteksi)
    if (logFile.is_open()) {
        std::string timestamp = getCurrentTime();
        logFile << "[" << timestamp << "] Oblivion Eye Stopped\n";
        logFile << "========================\n\n";
        logFile.close();
    }
}