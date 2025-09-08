#pragma once
#include <atomic>

namespace OblivionEye {
    class SignatureScanner {
    public:
        static SignatureScanner& Instance();
        void Start(unsigned intervalMs = 20000);
        void Stop();
    private:
        SignatureScanner() = default;
        void Loop(unsigned intervalMs);
        bool ScanMemory();
        bool ScanModule(HMODULE hMod, const wchar_t* modName);
        std::atomic<bool> m_running{ false };
    };
}
