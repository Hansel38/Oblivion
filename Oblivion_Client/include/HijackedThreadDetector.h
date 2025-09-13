#pragma once
#include "IDetector.h"

namespace OblivionEye {
    class HijackedThreadDetector : public IDetector {
    public:
        static HijackedThreadDetector& Instance();
        const wchar_t* Name() const override { return L"HijackedThreadDetector"; }
        unsigned IntervalMs() const override { return 7000; }
        void Tick() override;
        void Start(unsigned intervalMs = 7000) { (void)intervalMs; }
        void Stop() {}
    private:
        HijackedThreadDetector() = default;
        bool ScanThreads();
    };
}
