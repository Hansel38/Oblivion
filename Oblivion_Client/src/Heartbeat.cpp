#include "../pch.h"
#include "../include/Heartbeat.h"
#include "../include/Logger.h"
#include "../include/EventReporter.h"
#include <thread>
#include <chrono>

namespace OblivionEye {
    Heartbeat& Heartbeat::Instance() { static Heartbeat hb; return hb; }

    void Heartbeat::Start(unsigned intervalMs) {
        if (m_running.exchange(true)) return;
        std::thread([this, intervalMs]() { Loop(intervalMs); }).detach();
    }

    void Heartbeat::Stop() { m_running = false; }

    void Heartbeat::TriggerNow() {
        Log(L"Heartbeat tick (forced)");
        EventReporter::SendInfo(L"Heartbeat", L"forced");
    }

    void Heartbeat::Loop(unsigned intervalMs) {
        Log(L"Heartbeat start");
        while (m_running) {
            Log(L"Heartbeat tick");
            EventReporter::SendInfo(L"Heartbeat", L"tick");
            std::this_thread::sleep_for(std::chrono::milliseconds(intervalMs));
        }
        Log(L"Heartbeat stop");
    }
}
