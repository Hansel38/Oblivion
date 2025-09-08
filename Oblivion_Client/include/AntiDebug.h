#pragma once
#include <atomic>

namespace OblivionEye {
    class AntiDebug {
    public:
        static AntiDebug& Instance();
        void Start(unsigned intervalMs = 3000);
        void Stop();
    private:
        AntiDebug() = default;
        void Loop(unsigned intervalMs);
        bool DetectDebugger();
        std::atomic<bool> m_running{ false };
    };
}
