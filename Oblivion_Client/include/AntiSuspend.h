#pragma once
#include "IDetector.h"

namespace OblivionEye {
    class AntiSuspend : public IDetector {
    public:
        static AntiSuspend& Instance();
        const wchar_t* Name() const override { return L"AntiSuspend"; }
        unsigned IntervalMs() const override { return 2000; }
        void Tick() override;
        void Start(unsigned intervalMs = 2000) { (void)intervalMs; }
        void Stop() {}
    private:
        AntiSuspend() = default;
    };
}
