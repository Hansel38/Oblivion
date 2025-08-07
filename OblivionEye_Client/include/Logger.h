#pragma once
#include <string>

// Definisikan enum di luar class dengan cara yang lebih kompatibel
enum LogLevel {
    LOG_INFO = 0,
    LOG_WARNING = 1,
    LOG_ERROR = 2,
    LOG_DETECTED = 3
};

class Logger {
public:
    static void Initialize(const std::string& logFileName);
    static void Log(LogLevel level, const std::string& message);
    static void Close();

private:
    static void WriteLog(LogLevel level, const std::string& message);
    static std::string GetTimestamp();
    static std::string LogLevelToString(LogLevel level);
};