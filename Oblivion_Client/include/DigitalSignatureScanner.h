#pragma once
#include <atomic>
#include <string>

namespace OblivionEye {
    class DigitalSignatureScanner {
    public:
        static DigitalSignatureScanner& Instance();
        void Start(unsigned intervalMs = 15000);
        void Stop();
        void AddCriticalPath(const std::wstring& path);
    private:
        DigitalSignatureScanner() = default;
        void Loop(unsigned intervalMs);
        bool ScanPaths();
        std::atomic<bool> m_running{ false };
    };
}
