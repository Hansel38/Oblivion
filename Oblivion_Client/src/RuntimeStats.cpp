#include "../pch.h"
#include "../include/RuntimeStats.h"
#include <windows.h>

namespace OblivionEye {
RuntimeStats &RuntimeStats::Instance() { static RuntimeStats s; return s; }

void RuntimeStats::IncDetection()  { m_detections.fetch_add(1, std::memory_order_relaxed); }
void RuntimeStats::IncInfo()       { m_info.fetch_add(1, std::memory_order_relaxed); }
void RuntimeStats::IncHeartbeat()  { m_heartbeats.fetch_add(1, std::memory_order_relaxed); }
void RuntimeStats::IncAwNtdll()    { m_awNtdll.fetch_add(1, std::memory_order_relaxed); }
void RuntimeStats::IncAwKernel32() { m_awKernel32.fetch_add(1, std::memory_order_relaxed); }
void RuntimeStats::IncAwUser32()   { m_awUser32.fetch_add(1, std::memory_order_relaxed); }
void RuntimeStats::IncAwGdi32()    { m_awGdi32.fetch_add(1, std::memory_order_relaxed); }

void RuntimeStats::SetStartTick() {
    std::lock_guard<std::mutex> lk(m_mtx);
    m_startTick = GetTickCount64();
}

StatsSnapshot RuntimeStats::GetSnapshot() {
    StatsSnapshot s;
    s.detections  = m_detections.load();
    s.infoEvents  = m_info.load();
    s.heartbeats  = m_heartbeats.load();
    s.awNtdll     = m_awNtdll.load();
    s.awKernel32  = m_awKernel32.load();
    s.awUser32    = m_awUser32.load();
    s.awGdi32     = m_awGdi32.load();
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
