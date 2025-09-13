#pragma once
#include "IDetector.h"

namespace OblivionEye {
    class TestModeSpoofChecker : public IDetector {
    public:
        static TestModeSpoofChecker& Instance();
        const wchar_t* Name() const override { return L"TestModeSpoofChecker"; }
        unsigned IntervalMs() const override { return 30000; }
        void Tick() override;
        void Start(unsigned intervalMs = 30000) { (void)intervalMs; }
        void Stop() {}
    private:
        TestModeSpoofChecker() = default;
        bool DetectSpoof();
    };
}
