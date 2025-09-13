#pragma once
#include "IDetector.h"

namespace OblivionEye {
    class IATHookChecker : public IDetector {
    public:
        static IATHookChecker& Instance();
        const wchar_t* Name() const override { return L"IATHookChecker"; }
        unsigned IntervalMs() const override { return 30000; }
        void Tick() override;
        void Start(unsigned intervalMs = 30000) { (void)intervalMs; }
        void Stop() {}
    private:
        IATHookChecker() = default;
        bool ScanIAT();
        bool ScanModuleIAT(HMODULE hMod);
    };
}
