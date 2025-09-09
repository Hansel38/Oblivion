#pragma once
#include <atomic>
#include <vector>

namespace OblivionEye {
    class NtdllIntegrity {
    public:
        static NtdllIntegrity& Instance();
        void Start(unsigned intervalMs = 60000); // default 60s
        void Stop();
    private:
        NtdllIntegrity() = default;
        void Loop(unsigned intervalMs);
        bool Check();
        void CaptureBaseline();
        bool CaptureSubsectionHashes();
        bool m_baselineCaptured = false;
        unsigned long long m_baselineHash = 0ULL;
        std::vector<unsigned long long> m_chunkHashes; // delta hashing baseline
        std::atomic<bool> m_running{ false };
    };
}
