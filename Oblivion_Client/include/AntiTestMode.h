#pragma once
#include <atomic>
#include "IDetector.h"

namespace OblivionEye {
    class AntiTestMode : public IDetector {
    public:
        static AntiTestMode& Instance();
        // Implementasi IDetector
        const wchar_t* Name() const override { return L"AntiTestMode"; }
        unsigned IntervalMs() const override { return 15000; }
        void Tick() override; // satu scan
        // Legacy Start/Stop dipertahankan (no-op) untuk kompatibilitas sementara
        void Start(unsigned intervalMs = 15000) { (void)intervalMs; }
        void Stop() {}
    private:
        AntiTestMode() = default;
        bool IsTestModeEnabled();
    };
}
