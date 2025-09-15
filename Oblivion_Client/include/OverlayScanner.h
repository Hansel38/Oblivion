#pragma once
#include <atomic>
#include <windows.h>
#include "IDetector.h"

namespace OblivionEye {
    class OverlayScanner : public IDetector {
    public:
        static OverlayScanner& Instance();
        // IDetector
        const wchar_t* Name() const override { return L"OverlayScanner"; }
        unsigned IntervalMs() const override { return 2000; }
        void Tick() override;
        // Legacy no-op
        void Start(unsigned intervalMs = 2000) { (void)intervalMs; }
        void Stop() {}
    private:
        OverlayScanner() = default;
    bool IsBlacklistedWindow(HWND hwnd);
    int ScorePotentialCheatEngine(HWND hwnd); // heuristik varian CE rebrand
    bool HeuristicDetectCheatEngine(HWND hwnd);
        static BOOL CALLBACK EnumWindowsThunk(HWND hwnd, LPARAM lParam);
    };
}
