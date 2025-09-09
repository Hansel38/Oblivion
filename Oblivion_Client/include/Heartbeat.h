#pragma once
#include <atomic>

namespace OblivionEye {
    class Heartbeat {
    public:
        static Heartbeat& Instance();
        void Start(unsigned intervalMs = 10000); // default 10 detik
        void Stop();
        void TriggerNow();
        // Set adaptif: enable/disable dynamic interval (default off)
        void EnableAdaptive(bool enable);
    private:
        Heartbeat() = default;
        void Loop(unsigned intervalMs);
        std::atomic<bool> m_running{ false };
        std::atomic<bool> m_adaptive{ false };
    };
}
