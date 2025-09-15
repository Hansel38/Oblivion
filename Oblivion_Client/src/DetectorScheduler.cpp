#include "../pch.h"
#include "../include/DetectorScheduler.h"
#include "../include/Logger.h"
#include "../include/PipeClient.h"
#include <windows.h>
#include <algorithm>
#include "../include/StringUtil.h"
#include "../include/Config.h"

namespace OblivionEye {
namespace {
    inline unsigned long long NowMs() { return GetTickCount64(); }

    inline std::string Narrow(const std::wstring &w) { return StringUtil::WideAsciiLossy(w); }
}

DetectorScheduler &DetectorScheduler::Instance() {
    static DetectorScheduler s; return s;
}

void DetectorScheduler::Add(IDetector *det) {
    if (!det) return;
    std::lock_guard<std::mutex> lk(m_mtx);

    // Avoid duplicates by name
    for (auto &e : m_entries)
        if (wcscmp(e.det->Name(), det->Name()) == 0)
            return;

    unsigned base = det->IntervalMs();
    if (auto it = m_overrides.find(det->Name()); it != m_overrides.end())
        base = it->second;

    m_entries.push_back(Entry{ det, base, det->IntervalMs(), 0, 0, 0, 0.0, 0, false });
}

void DetectorScheduler::Start() {
    if (m_running.exchange(true))
        return;
    std::thread([this]() { Loop(); }).detach();
}

void DetectorScheduler::Stop() { m_running = false; }

std::vector<DetectorProfileEntry> DetectorScheduler::GetProfiles() {
    std::lock_guard<std::mutex> lk(m_mtx);
    std::vector<DetectorProfileEntry> out;
    out.reserve(m_entries.size());
    for (auto &e : m_entries) {
        double avg = e.runCount ? (e.accumDurationMs / static_cast<double>(e.runCount)) : 0.0;
        out.push_back({ e.det->Name(), e.runCount, e.lastDurationMs, avg });
    }
    return out;
}

void DetectorScheduler::ResetProfiles() {
    std::lock_guard<std::mutex> lk(m_mtx);
    for (auto &e : m_entries) {
        e.runCount = 0;
        e.lastDurationMs = 0;
        e.accumDurationMs = 0;
        e.slowStreak = 0;
        e.alerted = false;
    }
}

bool DetectorScheduler::SetIntervalOverride(const std::wstring &name, unsigned newIntervalMs) {
    std::lock_guard<std::mutex> lk(m_mtx);
    m_overrides[name] = newIntervalMs;
    bool updated = false;
    auto now = NowMs();
    for (auto &e : m_entries) {
        if (name == e.det->Name()) {
            e.interval = newIntervalMs;
            e.nextDue = now + newIntervalMs;
            updated = true;
        }
    }
    return updated;
}

unsigned DetectorScheduler::GetInterval(const std::wstring &name) {
    std::lock_guard<std::mutex> lk(m_mtx);
    for (auto &e : m_entries)
        if (name == e.det->Name())
            return e.interval;
    if (auto it = m_overrides.find(name); it != m_overrides.end())
        return it->second;
    return 0;
}

std::unordered_map<std::wstring, unsigned> DetectorScheduler::GetIntervalOverrides() {
    std::lock_guard<std::mutex> lk(m_mtx);
    return m_overrides;
}

std::vector<DetectorIntervalEntry> DetectorScheduler::GetAllIntervals() {
    std::lock_guard<std::mutex> lk(m_mtx);
    std::vector<DetectorIntervalEntry> v;
    v.reserve(m_entries.size());
    for (auto &e : m_entries) {
        bool overridden = m_overrides.find(e.det->Name()) != m_overrides.end();
        v.push_back({ e.det->Name(), e.interval, overridden });
    }
    return v;
}

bool DetectorScheduler::ClearIntervalOverride(const std::wstring &name) {
    std::lock_guard<std::mutex> lk(m_mtx);
    auto it = m_overrides.find(name);
    if (it == m_overrides.end()) return false;
    m_overrides.erase(it);
    auto now = NowMs();
    for (auto &e : m_entries) {
        if (name == e.det->Name()) {
            e.interval = e.baseInterval;
            e.nextDue = now + e.interval;
        }
    }
    return true;
}

void DetectorScheduler::ClearAllIntervalOverrides() {
    std::lock_guard<std::mutex> lk(m_mtx);
    m_overrides.clear();
    auto now = NowMs();
    for (auto &e : m_entries) {
        e.interval = e.baseInterval;
        e.nextDue = now + e.interval;
    }
}

unsigned DetectorScheduler::AdaptiveReset() {
    std::lock_guard<std::mutex> lk(m_mtx);
    unsigned long long now = NowMs();
    unsigned changed = 0;
    for (auto &e : m_entries) {
        if (m_overrides.find(e.det->Name()) != m_overrides.end())
            continue;
        if (e.interval != e.baseInterval) {
            e.interval = e.baseInterval;
            e.nextDue = now + e.interval;
            ++changed;
        }
    }
    return changed;
}

void DetectorScheduler::AdaptiveAdjust(Entry &e) {
    if (e.runCount < 5) return; // need baseline samples

    double avg = e.accumDurationMs / static_cast<double>(e.runCount);
    unsigned cap = e.baseInterval * Config::ADAPT_INTERVAL_MULT_MAX; // hard upper bound
    bool hasOverride = (m_overrides.find(e.det->Name()) != m_overrides.end());

    if (hasOverride) return; // do not adapt overridden entries

    if (avg > Config::ADAPT_INCREASE_THRESHOLD && e.interval < cap) {
        e.interval = (std::min)(cap, e.interval + e.baseInterval);
        Log(std::wstring(L"[Adaptive] Increased interval for ") + e.det->Name() +
            L" to " + std::to_wstring(e.interval));
    } else if (avg < Config::ADAPT_DECREASE_THRESHOLD && e.interval > e.baseInterval) {
        unsigned newInt = e.interval - e.baseInterval;
        if (newInt < e.baseInterval)
            newInt = e.baseInterval;
        if (newInt != e.interval) {
            e.interval = newInt;
            Log(std::wstring(L"[Adaptive] Decreased interval for ") + e.det->Name() +
                L" to " + std::to_wstring(e.interval));
        }
    }
}

std::vector<SelfTestResult> DetectorScheduler::RunSelfTest() {
    std::vector<SelfTestResult> results;
    std::lock_guard<std::mutex> lk(m_mtx);

    LARGE_INTEGER freq; QueryPerformanceFrequency(&freq);
    LARGE_INTEGER t1, t2;

    for (auto &e : m_entries) {
        double ms = -1.0;
        try {
            QueryPerformanceCounter(&t1);
            e.det->Tick();
            QueryPerformanceCounter(&t2);
            ms = (t2.QuadPart - t1.QuadPart) * 1000.0 / static_cast<double>(freq.QuadPart);
        } catch (...) {
            ms = -1.0;
        }
        results.push_back({ e.det->Name(), ms });
    }
    return results;
}

std::vector<ProfilerDetailEntry> DetectorScheduler::GetProfilerDetails() {
    std::lock_guard<std::mutex> lk(m_mtx);
    std::vector<ProfilerDetailEntry> out;
    out.reserve(m_entries.size());
    for (auto &e : m_entries) {
        bool overridden = m_overrides.find(e.det->Name()) != m_overrides.end();
        bool adaptive = (!overridden && e.interval != e.baseInterval);
        double avg = e.runCount ? (e.accumDurationMs / static_cast<double>(e.runCount)) : 0.0;
        out.push_back({ e.det->Name(), e.runCount, e.lastDurationMs, avg, e.interval, e.baseInterval, overridden, adaptive });
    }
    return out;
}

std::vector<QueueSnapshotEntry> DetectorScheduler::GetQueueSnapshot() {
    std::lock_guard<std::mutex> lk(m_mtx);
    std::vector<QueueSnapshotEntry> out;
    out.reserve(m_entries.size());
    unsigned long long now = NowMs();
    for (auto &e : m_entries) {
        unsigned remaining = 0;
        if (e.nextDue > now) {
            auto diff = e.nextDue - now;
            remaining = diff > 0xFFFFFFFFull ? 0xFFFFFFFFu : static_cast<unsigned>(diff);
        }
        bool overridden = m_overrides.find(e.det->Name()) != m_overrides.end();
        bool adaptive = (!overridden && e.interval != e.baseInterval);
        out.push_back({ e.det->Name(), remaining, e.interval, overridden, adaptive });
    }
    return out;
}

void DetectorScheduler::Loop() {
    Log(L"DetectorScheduler start");

    {
        std::lock_guard<std::mutex> lk(m_mtx);
        auto now = NowMs();
        for (auto &e : m_entries)
            e.nextDue = now + e.interval;
    }

    LARGE_INTEGER freq; QueryPerformanceFrequency(&freq);

    while (m_running) {
        std::vector<Entry *> due;
        unsigned long long now = NowMs();
        unsigned sleepFor = 100; // default tick

        // Collect due detectors & compute sleep
        {
            std::lock_guard<std::mutex> lk(m_mtx);
            for (auto &e : m_entries) {
                if (now >= e.nextDue) {
                    due.push_back(&e);
                    e.nextDue = now + e.interval;
                }
                unsigned long long remain = (e.nextDue > now) ? (e.nextDue - now) : 0ull;
                if (remain < sleepFor)
                    sleepFor = static_cast<unsigned>(remain);
            }
        }

        // Execute due detectors without holding lock
        for (auto *e : due) {
            LARGE_INTEGER t1, t2; QueryPerformanceCounter(&t1);
            try { e->det->Tick(); } catch (...) { Log(L"Detector tick exception"); }
            QueryPerformanceCounter(&t2);

            double ms = (t2.QuadPart - t1.QuadPart) * 1000.0 / static_cast<double>(freq.QuadPart);
            e->lastDurationMs = ms;
            e->runCount++;
            e->accumDurationMs += ms;

            if (ms >= m_slowThresholdMs) {
                e->slowStreak++;
            } else {
                e->slowStreak = 0;
                e->alerted = false;
            }

            if (!e->alerted && e->slowStreak >= m_slowAlertStreak) {
                Log(std::wstring(L"[Alert] Slow detector ") + e->det->Name() +
                    L" streak=" + std::to_wstring(e->slowStreak) +
                    L" last=" + std::to_wstring(static_cast<int>(ms)) + L"ms");

                if (PipeClient::Instance().IsRunning()) {
                    std::string msg = "INFO|ALERT|SLOW_DETECTOR|name=" + Narrow(e->det->Name()) +
                                      " last=" + std::to_string(static_cast<int>(ms)) + "ms avg=" +
                                      std::to_string(static_cast<int>(e->accumDurationMs / static_cast<double>(e->runCount))) +
                                      "ms streak=" + std::to_string(e->slowStreak);
                    PipeClient::Instance().Send(msg);
                }
                e->alerted = true;
            }
            AdaptiveAdjust(*e);
        }

    if (sleepFor < Config::SCHED_MIN_SLEEP_MS) sleepFor = Config::SCHED_MIN_SLEEP_MS; // clamp
        std::this_thread::sleep_for(std::chrono::milliseconds(sleepFor));
    }

    Log(L"DetectorScheduler stop");
}

} // namespace OblivionEye
