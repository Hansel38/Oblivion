#pragma once
#include <Windows.h>
#include <string>

// Definisikan enum LogLevel di luar namespace untuk menghindari masalah
enum Logger_Level {
    LOGGER_DEBUG,
    LOGGER_INFO,
    LOGGER_WARNING,
    LOGGER_ERROR,
    LOGGER_CRITICAL
};

namespace Logger {
    void Initialize(const std::wstring& logFile);
    void SetLogLevel(Logger_Level level);
    void Debug(const std::wstring& message);
    void Info(const std::wstring& message);
    void Warning(const std::wstring& message);
    void Error(const std::wstring& message);
    void Critical(const std::wstring& message);
    void CheatDetected(const std::wstring& detectionType, const std::wstring& details);
    void Flush();
}