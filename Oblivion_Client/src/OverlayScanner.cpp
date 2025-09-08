#include "../pch.h"
#include "../include/OverlayScanner.h"
#include "../include/OverlayBlacklist.h"
#include "../include/Utils.h"
#include "../include/Logger.h"
#include "../include/EventReporter.h"
#include <windows.h>
#include <thread>
#include <string>
#include <algorithm>

namespace OblivionEye {

    OverlayScanner& OverlayScanner::Instance() { static OverlayScanner s; return s; }

    void OverlayScanner::Start(unsigned intervalMs) {
        if (m_running.exchange(true)) return;
        std::thread([this, intervalMs]() { Loop(intervalMs); }).detach();
    }

    void OverlayScanner::Stop() { m_running = false; }

    bool OverlayScanner::IsBlacklistedWindow(HWND hwnd) {
        wchar_t title[256] = {};
        wchar_t cls[128] = {};
        GetWindowTextW(hwnd, title, 256);
        GetClassNameW(hwnd, cls, 128);

        std::wstring titleL = ToLower(title);
        std::wstring clsL = ToLower(cls);

        for (const auto& t : GetBlacklistedWindowTitles()) {
            if (!t.empty() && titleL.find(t) != std::wstring::npos) {
                EventReporter::SendDetection(L"OverlayScanner", title);
                return true;
            }
        }
        for (const auto& c : GetBlacklistedWindowClasses()) {
            if (!c.empty() && clsL.find(c) != std::wstring::npos) {
                EventReporter::SendDetection(L"OverlayScanner", cls);
                return true;
            }
        }
        return false;
    }

    BOOL CALLBACK OverlayScanner::EnumWindowsThunk(HWND hwnd, LPARAM lParam) {
        auto self = reinterpret_cast<OverlayScanner*>(lParam);
        if (!IsWindowVisible(hwnd)) return TRUE;
        if (self->IsBlacklistedWindow(hwnd)) {
            wchar_t t[256] = {}; GetWindowTextW(hwnd, t, 256);
            ShowDetectionAndExit(std::wstring(L"Overlay: ") + t);
            return FALSE;
        }
        return TRUE;
    }

    void OverlayScanner::Loop(unsigned intervalMs) {
        Log(L"OverlayScanner start");
        while (m_running) {
            EnumWindows(OverlayScanner::EnumWindowsThunk, reinterpret_cast<LPARAM>(this));
            std::this_thread::sleep_for(std::chrono::milliseconds(intervalMs));
        }
        Log(L"OverlayScanner stop");
    }
}
