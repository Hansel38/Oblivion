#include "../pch.h"
#include "../include/Heartbeat.h"
#include "../include/Logger.h"
#include "../include/EventReporter.h"

namespace OblivionEye {
namespace {
    constexpr unsigned MAX_ADAPTIVE_INTERVAL_MS = 60000; // 60s
    constexpr unsigned ADAPTIVE_GROWTH_FACTOR = 2;        // doubling
    constexpr unsigned ADAPTIVE_STEP_TRIGGER = 3;         // grow after N ticks
}

Heartbeat &Heartbeat::Instance() { static Heartbeat hb; return hb; }

void Heartbeat::EnableAdaptive(bool enable) {
    m_adaptive = enable;
    if (!enable) {
        m_currentInterval = IntervalMs();
        m_idleStreak = 0;
    }
}

void Heartbeat::TriggerNow() { EventReporter::SendInfo(L"Heartbeat", L"forced"); }

void Heartbeat::Tick() {
    EventReporter::SendInfo(L"Heartbeat", L"tick");

    if (!m_adaptive) {
        m_currentInterval = IntervalMs();
        return;
    }

    if (++m_idleStreak % ADAPTIVE_STEP_TRIGGER == 0 && m_currentInterval < MAX_ADAPTIVE_INTERVAL_MS) {
        unsigned long long next = static_cast<unsigned long long>(m_currentInterval) * ADAPTIVE_GROWTH_FACTOR;
        if (next > MAX_ADAPTIVE_INTERVAL_MS)
            next = MAX_ADAPTIVE_INTERVAL_MS;
        m_currentInterval = static_cast<unsigned>(next);
    }
}
}
