#include "../pch.h"
#include "../include/RuntimeStats.h"
#include <windows.h>

namespace OblivionEye {
RuntimeStats &RuntimeStats::Instance() { static RuntimeStats s; return s; }

void RuntimeStats::IncDetection()  { m_detections.fetch_add(1, std::memory_order_relaxed); }
void RuntimeStats::IncInfo()       { m_info.fetch_add(1, std::memory_order_relaxed); }
void RuntimeStats::IncHeartbeat()  { m_heartbeats.fetch_add(1, std::memory_order_relaxed); }

void RuntimeStats::SetStartTick() {
    std::lock_guard<std::mutex> lk(m_mtx);
    m_startTick = GetTickCount64();
}

StatsSnapshot RuntimeStats::GetSnapshot() {
    StatsSnapshot s;
    s.detections  = m_detections.load();
    s.infoEvents  = m_info.load();
    s.heartbeats  = m_heartbeats.load();
    uint64_t now  = GetTickCount64();
    uint64_t base = 0;
    {
        std::lock_guard<std::mutex> lk(m_mtx);
        base = m_startTick;
    }
    s.lastUptimeSec = base ? (now - base) / 1000 : 0;
    return s;
}
}
