#pragma once
#include "IDetector.h"

namespace OblivionEye {
    class SignatureScanner : public IDetector {
    public:
        static SignatureScanner& Instance();
        const wchar_t* Name() const override { return L"SignatureScanner"; }
        unsigned IntervalMs() const override { return 20000; }
        void Tick() override; // scan memory once
        void Start(unsigned intervalMs = 20000) { (void)intervalMs; }
        void Stop() {}
    private:
        SignatureScanner() = default;
        bool ScanMemory();
        bool ScanModule(HMODULE hMod, const wchar_t* modName);
    };
}
