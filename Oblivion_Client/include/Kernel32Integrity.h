#pragma once
#include <atomic>
#include <vector>

namespace OblivionEye {
    class Kernel32Integrity {
    public:
        static Kernel32Integrity& Instance();
        void Start(unsigned intervalMs = 60000); // default 60s
        void Stop();
    private:
        Kernel32Integrity() = default;
        void Loop(unsigned intervalMs);
        bool Check();
        void CaptureBaseline();
        bool CaptureSubsectionHashes();
        bool m_baselineCaptured = false;
        unsigned long long m_baselineHash = 0ULL;
        std::vector<unsigned long long> m_chunkHashes;
        std::atomic<bool> m_running{ false };
    };
}
