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

    void Heartbeat::EnableAdaptive(bool enable) { m_adaptive = enable; }

    void Heartbeat::TriggerNow() {
        Log(L"Heartbeat tick (forced)");
        EventReporter::SendInfo(L"Heartbeat", L"forced");
    }

    void Heartbeat::Loop(unsigned intervalMs) {
        Log(L"Heartbeat start");
        unsigned idleStreak = 0;
        unsigned currentInterval = intervalMs;
        while (m_running) {
            Log(L"Heartbeat tick");
            EventReporter::SendInfo(L"Heartbeat", L"tick");
            // Adaptif sederhana: jika tidak ada deteksi (hanya heartbeat), perpanjang interval sampai max 60 detik.
            if (m_adaptive) {
                ++idleStreak;
                if (idleStreak % 3 == 0 && currentInterval < 60000) { // tiap 3 tick naikkan
                    currentInterval = (unsigned)std::min<unsigned long long>(60000ULL, (unsigned long long)(currentInterval * 2ULL));
                    Log(L"Heartbeat adaptive interval -> " + std::to_wstring(currentInterval) + L" ms");
                }
            } else {
                currentInterval = intervalMs;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(currentInterval));
        }
        Log(L"Heartbeat stop");
    }
}
