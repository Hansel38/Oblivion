#pragma once
#include "IDetector.h"

namespace OblivionEye {
    class AntiDebug : public IDetector {
    public:
        static AntiDebug& Instance();
        const wchar_t* Name() const override { return L"AntiDebug"; }
        unsigned IntervalMs() const override { return 3000; }
        void Tick() override;
        void Start(unsigned intervalMs = 3000) { (void)intervalMs; }
        void Stop() {}
    private:
        AntiDebug() = default;
        bool DetectDebugger();
    };
}
