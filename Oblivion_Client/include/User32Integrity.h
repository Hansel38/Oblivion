#pragma once
#include "IDetector.h"
#include <vector>

namespace OblivionEye {
    class User32Integrity : public IDetector {
    public:
        static User32Integrity& Instance();
        const wchar_t* Name() const override { return L"User32Integrity"; }
        unsigned IntervalMs() const override { return 90000; }
        void Tick() override;
        void Start(unsigned intervalMs = 90000) { (void)intervalMs; }
        void Stop() {}
    private:
        User32Integrity() = default;
        bool Check(); void CaptureBaseline(); bool CaptureSubsectionHashes();
        bool m_baselineCaptured = false; unsigned long long m_baselineHash = 0ULL; std::vector<unsigned long long> m_chunkHashes;
        // Disk reference snapshot
        bool m_diskCaptured=false; unsigned long long m_diskHash=0ULL; std::vector<unsigned long long> m_diskChunkHashes;
    };
}
