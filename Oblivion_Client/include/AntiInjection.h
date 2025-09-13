#pragma once
#include <atomic>
#include "IDetector.h"

namespace OblivionEye {
    class AntiInjection : public IDetector {
    public:
        static AntiInjection& Instance();
        // IDetector impl
        const wchar_t* Name() const override { return L"AntiInjection"; }
        unsigned IntervalMs() const override { return 5000; }
        void Tick() override; // single scan
        // Legacy API (no-op)
        void Start(unsigned intervalMs = 5000) { (void)intervalMs; }
        void Stop() {}
    private:
        AntiInjection() = default;
        bool ScanModules();
    };
}
