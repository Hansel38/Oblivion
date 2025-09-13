#pragma once
#include "IDetector.h"
#include <vector>

namespace OblivionEye {
    class NtdllIntegrity : public IDetector {
    public:
        static NtdllIntegrity& Instance();
        const wchar_t* Name() const override { return L"NtdllIntegrity"; }
        unsigned IntervalMs() const override { return 60000; }
        void Tick() override; // perform integrity check
        void Start(unsigned intervalMs = 60000) { (void)intervalMs; }
        void Stop() {}
    private:
        NtdllIntegrity() = default;
        bool Check();
        void CaptureBaseline();
        bool CaptureSubsectionHashes();
        bool m_baselineCaptured = false;
        unsigned long long m_baselineHash = 0ULL;
        std::vector<unsigned long long> m_chunkHashes;
    };
}
