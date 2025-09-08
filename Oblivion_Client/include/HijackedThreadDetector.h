#pragma once
#include <atomic>

namespace OblivionEye {
    class HijackedThreadDetector {
    public:
        static HijackedThreadDetector& Instance();
        void Start(unsigned intervalMs = 7000);
        void Stop();
    private:
        HijackedThreadDetector() = default;
        void Loop(unsigned intervalMs);
        bool ScanThreads();
        std::atomic<bool> m_running{ false };
    };
}
