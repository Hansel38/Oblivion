#pragma once
#include <atomic>

namespace OblivionEye {
    class Heartbeat {
    public:
        static Heartbeat& Instance();
        void Start(unsigned intervalMs = 10000); // default 10 detik
        void Stop();
        // Trigger satu tick segera (untuk command REQUEST_HEARTBEAT_NOW)
        void TriggerNow();
    private:
        Heartbeat() = default;
        void Loop(unsigned intervalMs);
        std::atomic<bool> m_running{ false };
    };
}
