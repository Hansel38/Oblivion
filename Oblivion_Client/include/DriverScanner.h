#pragma once
#include <atomic>

namespace OblivionEye {
    class DriverScanner {
    public:
        static DriverScanner& Instance();
        void Start(unsigned intervalMs = 10000); // 10 detik
        void Stop();
    private:
        DriverScanner() = default;
        void Loop(unsigned intervalMs);
        bool IsBlacklistedLoaded();
        std::atomic<bool> m_running{ false };
    };
}
