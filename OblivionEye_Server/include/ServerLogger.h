#pragma once
#include <string>

// Enum untuk level log, mirip dengan client
enum ServerLogLevel {
    S_LOG_INFO,
    S_LOG_WARNING,
    S_LOG_ERROR,
    S_LOG_CLIENT_CONN,  // Khusus untuk koneksi client
    S_LOG_CLIENT_DATA,  // Khusus untuk data dari client
    S_LOG_VALIDATION    // Khusus untuk proses validasi
};

class ServerLogger {
public:
    static void Initialize(const std::string& logFileName);
    static void Log(ServerLogLevel level, const std::string& message);
    static void Close();

private:
    static void WriteLog(ServerLogLevel level, const std::string& message);
    static std::string GetTimestamp();
    static std::string LogLevelToString(ServerLogLevel level);
};