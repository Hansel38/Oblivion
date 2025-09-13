#pragma once
#include <vector>
#include <atomic>
#include <thread>
#include <mutex>
#include <chrono>
#include <string>
#include <unordered_map>
#include <functional>
#include "IDetector.h"

namespace OblivionEye {
    struct DetectorProfileEntry { std::wstring name; unsigned long long runCount{0}; double lastDurationMs{0.0}; double avgDurationMs{0.0}; };
    struct DetectorIntervalEntry { std::wstring name; unsigned intervalMs{0}; bool overridden{false}; };
    struct SelfTestResult { std::wstring name; double durationMs{0.0}; };

    class DetectorScheduler {
    public:
        static DetectorScheduler& Instance();
        void Start();
        void Stop();
        void Add(IDetector* det);
        std::vector<DetectorProfileEntry> GetProfiles();
        void ResetProfiles();
        bool SetIntervalOverride(const std::wstring& name, unsigned newIntervalMs);
        unsigned GetInterval(const std::wstring& name);
        std::unordered_map<std::wstring, unsigned> GetIntervalOverrides();
        std::vector<DetectorIntervalEntry> GetAllIntervals();
        bool ClearIntervalOverride(const std::wstring& name);
        void ClearAllIntervalOverrides();
        std::vector<SelfTestResult> RunSelfTest();
    private:
        DetectorScheduler() = default;
        void Loop();
        struct Entry { IDetector* det; unsigned interval; unsigned baseInterval; unsigned long long nextDue; unsigned long long runCount; double lastDurationMs; double accumDurationMs; };
        std::vector<Entry> m_entries;
        std::unordered_map<std::wstring, unsigned> m_overrides;
        std::atomic<bool> m_running{ false };
        std::mutex m_mtx;
        void AdaptiveAdjust(Entry& e);
    };
}
