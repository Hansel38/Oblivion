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
    struct ProfilerDetailEntry { std::wstring name; unsigned long long runCount{0}; double lastMs{0.0}; double avgMs{0.0}; unsigned interval{0}; unsigned baseInterval{0}; bool overridden{false}; bool adaptive{false}; };
    struct QueueSnapshotEntry { std::wstring name; unsigned remainingMs{0}; unsigned intervalMs{0}; bool overridden{false}; bool adaptive{false}; };

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
        std::vector<ProfilerDetailEntry> GetProfilerDetails();
        std::vector<QueueSnapshotEntry> GetQueueSnapshot();
        void SetSlowThresholdMs(double ms) { m_slowThresholdMs = ms; }
        void SetSlowAlertStreak(unsigned n) { m_slowAlertStreak = n; }
        unsigned AdaptiveReset(); // reset adaptive intervals back; returns count changed
    private:
        DetectorScheduler() = default;
        void Loop();
        struct Entry { IDetector* det; unsigned interval; unsigned baseInterval; unsigned long long nextDue; unsigned long long runCount; double lastDurationMs; double accumDurationMs; unsigned slowStreak{0}; bool alerted{false}; };
        std::vector<Entry> m_entries;
        std::unordered_map<std::wstring, unsigned> m_overrides;
        std::atomic<bool> m_running{ false };
        std::mutex m_mtx;
        void AdaptiveAdjust(Entry& e);
        double m_slowThresholdMs = 120.0; // default threshold
        unsigned m_slowAlertStreak = 3;    // consecutive occurrences
    };
}
