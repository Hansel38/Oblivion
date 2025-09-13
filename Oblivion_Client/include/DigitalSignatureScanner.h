#pragma once
#include <string>
#include "IDetector.h"
#include <vector>
#include <mutex>

namespace OblivionEye {
    class DigitalSignatureScanner : public IDetector {
    public:
        static DigitalSignatureScanner& Instance();
        void AddCriticalPath(const std::wstring& path);
        // IDetector
        const wchar_t* Name() const override { return L"DigitalSignature"; }
        unsigned IntervalMs() const override { return 15000; }
        void Tick() override;
        // Legacy no-op
        void Start(unsigned intervalMs = 15000) { (void)intervalMs; }
        void Stop() {}
    private:
        DigitalSignatureScanner() = default;
        bool ScanPaths();
    };
}
