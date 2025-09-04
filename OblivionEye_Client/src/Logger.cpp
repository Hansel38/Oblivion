#include "../include/Logger.h"
#include <windows.h>
#include <fstream>
#include <iostream>
#include <ctime>
#include <iomanip>
#include <sstream>
#include "../include/Config.h"

static std::ofstream logFile;
std::mutex Logger::queueMutex;
std::condition_variable Logger::queueCv;
std::deque<Logger::LogItem> Logger::queue;
std::thread Logger::workerThread;
bool Logger::workerRunning = false;
size_t Logger::droppedMessages = 0;
std::string Logger::logFilePath;

static const size_t kMaxQueueSize = 4096; // ring buffer capacity

void Logger::Initialize(const std::string& logFileName) {
    auto& cfg = Config::Get();
    CreateDirectoryA(cfg.logFolder.c_str(), NULL);
    std::string targetName = logFileName.empty() ? cfg.logFileName : logFileName;
    logFilePath = cfg.logFolder + "\\" + targetName;
    logFile.open(logFilePath, std::ios::app);

    workerRunning = true;
    workerThread = std::thread(WorkerLoop);
    Log(LOG_INFO, cfg.logStartBanner);
}

void Logger::Log(LogLevel level, const std::string& message) {
    if (!workerRunning) return;
    {
        std::unique_lock<std::mutex> lock(queueMutex);
        if (queue.size() >= kMaxQueueSize) {
            // drop oldest (ring behaviour)
            queue.pop_front();
            ++droppedMessages;
        }
        queue.push_back({ level, message });
    }
    queueCv.notify_one();
}

void Logger::WorkerLoop() {
    while (workerRunning) {
        std::deque<LogItem> localBatch;
        {
            std::unique_lock<std::mutex> lock(queueMutex);
            queueCv.wait(lock, [] { return !workerRunning || !queue.empty(); });
            if (!workerRunning && queue.empty()) break;
            // move to local batch to minimize lock hold
            localBatch.swap(queue);
        }
        if (!logFile.is_open()) continue;
        for (auto& item : localBatch) {
            WriteDirect(item);
        }
        if (droppedMessages) {
            LogItem info{ LOG_WARNING, "Dropped log messages: " + std::to_string(droppedMessages) };
            WriteDirect(info);
            droppedMessages = 0; // reset after reporting
        }
        logFile.flush();
    }
}

void Logger::WriteDirect(const LogItem& item) {
    std::string timestamp = GetTimestamp();
    logFile << "[" << timestamp << "] [" << LogLevelToString(item.level) << "] " << item.message << std::endl;
    if (item.level == LOG_DETECTED) {
        OutputDebugStringA(("[OblivionEye] " + item.message + "\n").c_str());
    }
}

std::string Logger::GetTimestamp() {
    time_t rawtime; struct tm timeinfo; time(&rawtime); localtime_s(&timeinfo, &rawtime);
    char buffer[80]; strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &timeinfo);
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
    if (!workerRunning) return;
    Log(LOG_INFO, Config::Get().logStopBanner);
    {
        std::lock_guard<std::mutex> lock(queueMutex);
        workerRunning = false;
    }
    queueCv.notify_all();
    if (workerThread.joinable()) workerThread.join();
    // flush remaining (already flushed in worker loop). Close file.
    if (logFile.is_open()) logFile.close();
}