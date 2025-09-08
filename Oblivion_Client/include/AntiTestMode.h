#pragma once
#include <atomic>

namespace OblivionEye {
    class AntiTestMode {
    public:
        static AntiTestMode& Instance();
        void Start(unsigned intervalMs = 15000);
        void Stop();
    private:
        AntiTestMode() = default;
        void Loop(unsigned intervalMs);
        bool IsTestModeEnabled();
        std::atomic<bool> m_running{ false };
    };
}
