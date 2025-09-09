#pragma once
#include <atomic>
#include <vector>

namespace OblivionEye {
    class Gdi32Integrity {
    public:
        static Gdi32Integrity& Instance();
        void Start(unsigned intervalMs = 90000); // default 90s
        void Stop();
    private:
        Gdi32Integrity() = default;
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
