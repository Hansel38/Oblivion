#pragma once
#include <atomic>

namespace OblivionEye {
    class AntiInjection {
    public:
        static AntiInjection& Instance();
        void Start(unsigned intervalMs = 5000);
        void Stop();
    private:
        AntiInjection() = default;
        void Loop(unsigned intervalMs);
        bool ScanModules();
        std::atomic<bool> m_running{ false };
    };
}
