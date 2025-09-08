#pragma once
#include <atomic>

namespace OblivionEye {
    class AntiSuspend {
    public:
        static AntiSuspend& Instance();
        void Start(unsigned intervalMs = 2000);
        void Stop();
    private:
        AntiSuspend() = default;
        void Loop(unsigned intervalMs);
        std::atomic<bool> m_running{ false };
    };
}
