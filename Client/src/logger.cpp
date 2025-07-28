#include "../include/logger.h"
#include <fstream>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <ctime>
#include <mutex>
#include <cstring> // Untuk wcscpy_s

namespace {
    std::wstring logFileName;
    Logger_Level currentLogLevel = LOGGER_INFO;
    std::mutex logMutex;
    bool isInitialized = false;
}

namespace Logger {
    void Initialize(const std::wstring& logFile) {
        logFileName = logFile;
        isInitialized = true;

        // Buat file log baru (overwrite)
        std::wofstream logStream(logFile);
        if (logStream.is_open()) {
            auto now = std::chrono::system_clock::now();
            std::time_t now_c = std::chrono::system_clock::to_time_t(now);

            // Perbaikan: Gunakan localtime_s dan wcsftime
            std::tm tm_snapshot;
#if defined(_WIN32) || defined(_WIN64)
            localtime_s(&tm_snapshot, &now_c);
#else
            localtime_r(&now_c, &tm_snapshot);
#endif

            wchar_t time_buffer[100];
            std::wcsftime(time_buffer, sizeof(time_buffer) / sizeof(time_buffer[0]), L"%Y-%m-%d %H:%M:%S", &tm_snapshot);

            logStream << L"========================================" << std::endl;
            logStream << L"Oblivion Eye Anti-Cheat Log" << std::endl;
            logStream << L"Started at: " << time_buffer << std::endl;
            logStream << L"========================================" << std::endl;
            logStream.close();
        }
    }

    void SetLogLevel(Logger_Level level) {
        currentLogLevel = level;
    }

    std::wstring GetTimestamp() {
        auto now = std::chrono::system_clock::now();
        auto now_ms = std::chrono::time_point_cast<std::chrono::milliseconds>(now);
        auto value = now_ms.time_since_epoch();
        time_t now_c = std::chrono::system_clock::to_time_t(now);

        // Perbaikan: Gunakan localtime_s dan wcsftime
        std::tm tm_snapshot;
#if defined(_WIN32) || defined(_WIN64)
        localtime_s(&tm_snapshot, &now_c);
#else
        localtime_r(&now_c, &tm_snapshot);
#endif

        wchar_t time_buffer[100];
        std::wcsftime(time_buffer, sizeof(time_buffer) / sizeof(time_buffer[0]), L"%Y-%m-%d %H:%M:%S", &tm_snapshot);

        // Perbaikan: Gunakan count() untuk mendapatkan nilai numerik
        long long millis = value.count() % 1000;

        std::wstringstream ss;
        ss << time_buffer;
        ss << L"." << std::setfill(L'0') << std::setw(3) << millis;

        return ss.str();
    }

    void LogMessage(Logger_Level level, const std::wstring& message) {
        if (!isInitialized || level < currentLogLevel) {
            return;
        }

        std::wstring levelStr;
        switch (level) {
        case LOGGER_DEBUG: levelStr = L"DEBUG"; break;
        case LOGGER_INFO: levelStr = L"INFO"; break;
        case LOGGER_WARNING: levelStr = L"WARNING"; break;
        case LOGGER_ERROR: levelStr = L"ERROR"; break;
        case LOGGER_CRITICAL: levelStr = L"CRITICAL"; break;
        }

        std::wstring timestamp = GetTimestamp();
        std::wstring logEntry = timestamp + L" [" + levelStr + L"] " + message;

        // Tampilkan di console untuk debugging (hanya jika dalam mode debug)
#ifdef _DEBUG
        OutputDebugStringW((logEntry + L"\n").c_str());
#endif

        // Tulis ke file log
        std::lock_guard<std::mutex> lock(logMutex);
        std::wofstream logStream(logFileName, std::ios_base::app);
        if (logStream.is_open()) {
            logStream << logEntry << std::endl;
            logStream.close();
        }
    }

    void Debug(const std::wstring& message) {
        LogMessage(LOGGER_DEBUG, message);
    }

    void Info(const std::wstring& message) {
        LogMessage(LOGGER_INFO, message);
    }

    void Warning(const std::wstring& message) {
        LogMessage(LOGGER_WARNING, message);
    }

    void Error(const std::wstring& message) {
        LogMessage(LOGGER_ERROR, message);
    }

    void Critical(const std::wstring& message) {
        LogMessage(LOGGER_CRITICAL, message);
    }

    void CheatDetected(const std::wstring& detectionType, const std::wstring& details) {
        std::wstring message = L"Cheat detected! Type: " + detectionType + L", Details: " + details;
        LogMessage(LOGGER_CRITICAL, message);
    }

    void Flush() {
        // Pastikan semua log tertulis ke disk
        std::lock_guard<std::mutex> lock(logMutex);
    }
}