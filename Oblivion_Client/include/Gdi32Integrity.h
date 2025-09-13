#pragma once
#include "IDetector.h"
#include <vector>

namespace OblivionEye {
    class Gdi32Integrity : public IDetector {
    public:
        static Gdi32Integrity& Instance();
        const wchar_t* Name() const override { return L"Gdi32Integrity"; }
        unsigned IntervalMs() const override { return 90000; }
        void Tick() override;
        void Start(unsigned intervalMs = 90000) { (void)intervalMs; }
        void Stop() {}
    private:
        Gdi32Integrity() = default;
        bool Check(); void CaptureBaseline(); bool CaptureSubsectionHashes();
        bool m_baselineCaptured=false; unsigned long long m_baselineHash=0ULL; std::vector<unsigned long long> m_chunkHashes;
    };
}
