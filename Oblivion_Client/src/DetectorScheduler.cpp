#include "../pch.h"
#include "../include/DetectorScheduler.h"
#include "../include/Logger.h"
#include <algorithm>
#include <windows.h>

namespace OblivionEye {
    static unsigned long long GetMsNow() { return GetTickCount64(); }

    DetectorScheduler& DetectorScheduler::Instance() { static DetectorScheduler s; return s; }

    void DetectorScheduler::Add(IDetector* det) {
        if (!det) return; std::lock_guard<std::mutex> lk(m_mtx);
        for (auto& e : m_entries) { if (wcscmp(e.det->Name(), det->Name()) == 0) return; }
        unsigned base = det->IntervalMs(); auto it = m_overrides.find(det->Name()); if (it != m_overrides.end()) base = it->second;
        m_entries.push_back(Entry{ det, base, det->IntervalMs(), 0, 0, 0, 0.0 });
    }

    void DetectorScheduler::Start() { if (m_running.exchange(true)) return; std::thread([this]() { Loop(); }).detach(); }
    void DetectorScheduler::Stop() { m_running = false; }

    std::vector<DetectorProfileEntry> DetectorScheduler::GetProfiles() { std::lock_guard<std::mutex> lk(m_mtx); std::vector<DetectorProfileEntry> out; out.reserve(m_entries.size()); for (auto& e : m_entries) { out.push_back(DetectorProfileEntry{ e.det->Name(), e.runCount, e.lastDurationMs, e.runCount ? (e.accumDurationMs / (double)e.runCount) : 0.0 }); } return out; }
    void DetectorScheduler::ResetProfiles() { std::lock_guard<std::mutex> lk(m_mtx); for (auto& e : m_entries) { e.runCount = 0; e.lastDurationMs = 0; e.accumDurationMs = 0; } }
    bool DetectorScheduler::SetIntervalOverride(const std::wstring& name, unsigned newIntervalMs) { std::lock_guard<std::mutex> lk(m_mtx); m_overrides[name] = newIntervalMs; bool updated=false; for (auto& e : m_entries) { if (name == e.det->Name()) { e.interval = newIntervalMs; e.nextDue = GetMsNow() + newIntervalMs; updated=true; }} return updated; }
    unsigned DetectorScheduler::GetInterval(const std::wstring& name) { std::lock_guard<std::mutex> lk(m_mtx); for (auto& e : m_entries) if (name == e.det->Name()) return e.interval; auto it = m_overrides.find(name); if (it!=m_overrides.end()) return it->second; return 0; }
    std::unordered_map<std::wstring, unsigned> DetectorScheduler::GetIntervalOverrides() { std::lock_guard<std::mutex> lk(m_mtx); return m_overrides; }
    std::vector<DetectorIntervalEntry> DetectorScheduler::GetAllIntervals() { std::lock_guard<std::mutex> lk(m_mtx); std::vector<DetectorIntervalEntry> v; v.reserve(m_entries.size()); for(auto& e: m_entries){ bool ov = m_overrides.find(e.det->Name()) != m_overrides.end(); v.push_back(DetectorIntervalEntry{ e.det->Name(), e.interval, ov }); } return v; }
    bool DetectorScheduler::ClearIntervalOverride(const std::wstring& name) { std::lock_guard<std::mutex> lk(m_mtx); auto it=m_overrides.find(name); if(it==m_overrides.end()) return false; m_overrides.erase(it); for(auto& e: m_entries){ if(name==e.det->Name()){ e.interval = e.baseInterval; e.nextDue = GetMsNow() + e.interval; }} return true; }
    void DetectorScheduler::ClearAllIntervalOverrides() { std::lock_guard<std::mutex> lk(m_mtx); m_overrides.clear(); for(auto& e: m_entries){ e.interval = e.baseInterval; e.nextDue = GetMsNow() + e.interval; }}

    void DetectorScheduler::AdaptiveAdjust(Entry& e) {
        if (e.runCount < 5) return; // need sample size
        double avg = e.accumDurationMs / (double)e.runCount;
        unsigned cap = e.baseInterval * 4;
        if (avg > 75.0 && e.interval < cap && m_overrides.find(e.det->Name())==m_overrides.end()) {
            e.interval = (std::min)(cap, e.interval + e.baseInterval); // protect from macro min
            Log(std::wstring(L"[Adaptive] Increased interval for ") + e.det->Name() + L" to " + std::to_wstring(e.interval));
        } else if (avg < 25.0 && e.interval > e.baseInterval && m_overrides.find(e.det->Name())==m_overrides.end()) {
            unsigned newInt = e.interval > e.baseInterval ? (e.interval - e.baseInterval) : e.baseInterval;
            if (newInt < e.baseInterval) newInt = e.baseInterval;
            if (newInt != e.interval) {
                e.interval = newInt;
                Log(std::wstring(L"[Adaptive] Decreased interval for ") + e.det->Name() + L" to " + std::to_wstring(e.interval));
            }
        }
    }

    std::vector<SelfTestResult> DetectorScheduler::RunSelfTest() {
        std::vector<SelfTestResult> results; std::lock_guard<std::mutex> lk(m_mtx);
        LARGE_INTEGER freq; QueryPerformanceFrequency(&freq); LARGE_INTEGER t1,t2;
        for (auto& e : m_entries) {
            try { QueryPerformanceCounter(&t1); e.det->Tick(); QueryPerformanceCounter(&t2); double ms = (double)(t2.QuadPart - t1.QuadPart) * 1000.0 / (double)freq.QuadPart; results.push_back(SelfTestResult{ e.det->Name(), ms }); }
            catch (...) { results.push_back(SelfTestResult{ e.det->Name(), -1.0 }); }
        }
        return results;
    }

    void DetectorScheduler::Loop() {
        Log(L"DetectorScheduler start"); { std::lock_guard<std::mutex> lk(m_mtx); auto now = GetMsNow(); for (auto& e : m_entries) e.nextDue = now + e.interval; }
        LARGE_INTEGER freq; QueryPerformanceFrequency(&freq);
        while (m_running) {
            std::vector<Entry*> due; unsigned long long now = GetMsNow(); unsigned sleepFor = 100;
            { std::lock_guard<std::mutex> lk(m_mtx); for (auto& e : m_entries) { if (now >= e.nextDue) { due.push_back(&e); e.nextDue = now + e.interval; } unsigned long long remain = (e.nextDue > now) ? (e.nextDue - now) : 0ULL; if (remain < sleepFor) sleepFor = (unsigned)remain; } }
            for (auto* e : due) { LARGE_INTEGER t1,t2; QueryPerformanceCounter(&t1); try { e->det->Tick(); } catch (...) { Log(L"Detector tick exception"); } QueryPerformanceCounter(&t2); double ms = (double)(t2.QuadPart - t1.QuadPart) * 1000.0 / (double)freq.QuadPart; e->lastDurationMs = ms; e->runCount++; e->accumDurationMs += ms; AdaptiveAdjust(*e); }
            if (sleepFor < 10) sleepFor = 10; std::this_thread::sleep_for(std::chrono::milliseconds(sleepFor));
        }
        Log(L"DetectorScheduler stop");
    }
}
