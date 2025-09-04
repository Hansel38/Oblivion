#pragma once
#include <string>
#include <mutex>
#include <condition_variable>
#include <deque>
#include <thread>

// Log levels
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
    struct LogItem {
        LogLevel level;
        std::string message;
    };

    static void WorkerLoop();
    static void WriteDirect(const LogItem& item); // only called by worker
    static std::string GetTimestamp();
    static std::string LogLevelToString(LogLevel level);

    // concurrency
    static std::mutex queueMutex;
    static std::condition_variable queueCv;
    static std::deque<LogItem> queue;
    static std::thread workerThread;
    static bool workerRunning;
    static size_t droppedMessages;

    // file
    static std::string logFilePath;
};