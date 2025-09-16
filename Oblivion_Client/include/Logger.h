#pragma once
#include <string>
#include <vector>
#include <mutex>
#include <optional>

namespace OblivionEye {

    enum class LogLevel { Debug=0, Info=1, Warn=2, Error=3, Security=4 };

    struct LogEntry {
        unsigned long long tick; // GetTickCount64 snapshot
        LogLevel level;
        std::wstring message;
    };

    class LoggerBackend {
    public:
        static LoggerBackend& Instance();
        void SetLevel(LogLevel lvl);
        LogLevel GetLevel() const;
        void EnableFileSink(const std::wstring &path, bool append=true);
        void DisableFileSink();
        void SetMaxRing(size_t n); // adjust ring buffer size
        void Push(LogLevel lvl, const std::wstring &msg);
        std::vector<LogEntry> Snapshot(); // copy current ring buffer
    private:
        LoggerBackend() = default;
        void WriteFileLine(const std::wstring &line);
        LogLevel m_level = LogLevel::Info;
        std::mutex m_mtx;
        std::vector<LogEntry> m_ring;
        size_t m_ringMax = 256;
        size_t m_ringIndex = 0; // circular
        void* m_fileHandle = nullptr; // HANDLE but keep void* to avoid windows.h leak in header
    };

    // Backward compatible simple log (defaults to Info)
    void Log(const std::wstring& msg);
    void LogDbg(const std::wstring& msg); // Debug
    void LogWarn(const std::wstring& msg);
    void LogErr(const std::wstring& msg);
    void LogSec(const std::wstring& msg); // Security sensitive / tamper events
}
