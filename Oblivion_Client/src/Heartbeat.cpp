#include "../pch.h"
#include "../include/Heartbeat.h"
#include "../include/Logger.h"
#include "../include/EventReporter.h"

namespace OblivionEye {
    Heartbeat& Heartbeat::Instance() { static Heartbeat hb; return hb; }

    void Heartbeat::EnableAdaptive(bool enable) { m_adaptive = enable; if(!enable){ m_currentInterval = IntervalMs(); m_idleStreak = 0; } }

    void Heartbeat::TriggerNow() {
        EventReporter::SendInfo(L"Heartbeat", L"forced");
    }

    void Heartbeat::Tick() {
        EventReporter::SendInfo(L"Heartbeat", L"tick");
        if (m_adaptive) {
            ++m_idleStreak;
            if (m_idleStreak % 3 == 0 && m_currentInterval < 60000) {
                unsigned long long next = (unsigned long long)m_currentInterval * 2ULL;
                if (next > 60000ULL) next = 60000ULL;
                m_currentInterval = (unsigned)next;
            }
        } else {
            m_currentInterval = IntervalMs();
        }
    }
}
