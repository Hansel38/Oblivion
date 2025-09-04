#include "../include/DetectionController.h"
#include "../include/Logger.h"
#include <atomic>
#include <mutex>

namespace DetectionController {
    static std::atomic<bool> g_stopRequested{false};
    static std::atomic<bool> g_detectionTriggered{false};
    static std::string g_reason; 
    static std::mutex g_reasonMutex;

    void Initialize() {
        g_stopRequested = false;
        g_detectionTriggered = false;
        std::lock_guard<std::mutex> lk(g_reasonMutex);
        g_reason.clear();
    }

    void RequestShutdown() {
        g_stopRequested = true;
    }

    void ReportDetection(const std::string& reason) {
        bool expected = false;
        if (g_detectionTriggered.compare_exchange_strong(expected, true)) {
            {
                std::lock_guard<std::mutex> lk(g_reasonMutex);
                g_reason = reason;
            }
            Logger::Log(LOG_DETECTED, "Detection triggered: " + reason);
            // also request stop
            g_stopRequested = true;
        }
    }

    bool IsStopRequested() { return g_stopRequested.load(); }
    bool IsDetectionTriggered() { return g_detectionTriggered.load(); }
    std::string GetDetectionReason() { std::lock_guard<std::mutex> lk(g_reasonMutex); return g_reason; }
}
