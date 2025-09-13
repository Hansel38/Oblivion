#pragma once
#include "IDetector.h"
#include <vector>

namespace OblivionEye {
    class Kernel32Integrity : public IDetector {
    public:
        static Kernel32Integrity& Instance();
        const wchar_t* Name() const override { return L"Kernel32Integrity"; }
        unsigned IntervalMs() const override { return 60000; }
        void Tick() override;
        void Start(unsigned intervalMs = 60000) { (void)intervalMs; }
        void Stop() {}
    private:
        Kernel32Integrity() = default;
        bool Check();
        void CaptureBaseline();
        bool CaptureSubsectionHashes();
        bool m_baselineCaptured = false; unsigned long long m_baselineHash = 0ULL; std::vector<unsigned long long> m_chunkHashes;
    };
}
