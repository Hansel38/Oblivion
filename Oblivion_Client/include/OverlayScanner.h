#pragma once
#include <atomic>
#include <windows.h>

namespace OblivionEye {
    class OverlayScanner {
    public:
        static OverlayScanner& Instance();
        void Start(unsigned intervalMs = 2000);
        void Stop();
    private:
        OverlayScanner() = default;
        void Loop(unsigned intervalMs);
        bool IsBlacklistedWindow(HWND hwnd);
        static BOOL CALLBACK EnumWindowsThunk(HWND hwnd, LPARAM lParam);
        std::atomic<bool> m_running{ false };
    };
}
