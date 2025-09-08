#pragma once
#include <atomic>

namespace OblivionEye {
    class IATHookChecker {
    public:
        static IATHookChecker& Instance();
        void Start(unsigned intervalMs = 30000);
        void Stop();
    private:
        IATHookChecker() = default;
        void Loop(unsigned intervalMs);
        bool ScanIAT();
        bool ScanModuleIAT(HMODULE hMod);
        std::atomic<bool> m_running{ false };
    };
}
