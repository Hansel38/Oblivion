#include "../pch.h"
#include "../include/OverlayScanner.h"
#include "../include/OverlayBlacklist.h"
#include "../include/Utils.h"
#include "../include/Logger.h"
#include "../include/EventReporter.h"
#include "../include/PublisherWhitelist.h"
#include <windows.h>
#include <string>
#include <algorithm>

namespace OblivionEye {

    static bool IsOwnerProcessTrusted(HWND hwnd) {
        DWORD pid = 0;
        GetWindowThreadProcessId(hwnd, &pid);
        if (!pid) return false;
        HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!hProc) return false;
        wchar_t path[MAX_PATH];
        DWORD size = MAX_PATH;
        bool trusted = false;
        if (QueryFullProcessImageNameW(hProc, 0, path, &size)) {
            // Jika publisher file ini ada di whitelist, anggap overlay ini legitimate
            if (PublisherWhitelist::IsFileSignedByTrusted(path)) {
                trusted = true;
            }
        }
        CloseHandle(hProc);
        return trusted;
    }

    OverlayScanner& OverlayScanner::Instance() { static OverlayScanner s; return s; }

    bool OverlayScanner::IsBlacklistedWindow(HWND hwnd) {
        wchar_t title[256] = {};
        wchar_t cls[128] = {};
        GetWindowTextW(hwnd, title, 256);
        GetClassNameW(hwnd, cls, 128);

        std::wstring titleL = ToLower(title);
        std::wstring clsL = ToLower(cls);

        // Jika window berasal dari proses trusted publisher -> whitelist overlay tsb
        if (IsOwnerProcessTrusted(hwnd)) {
            return false; // skip semua pengecekan blacklist (overlay legit)
        }

        for (const auto& t : GetBlacklistedWindowTitles()) {
            if (!t.empty() && titleL.find(t) != std::wstring::npos) {
                EventReporter::SendDetection(L"OverlayScanner", title);
                ShowDetectionAndExit(std::wstring(L"Overlay: ") + title);
                return true;
            }
        }
        for (const auto& c : GetBlacklistedWindowClasses()) {
            if (!c.empty() && clsL.find(c) != std::wstring::npos) {
                EventReporter::SendDetection(L"OverlayScanner", cls);
                ShowDetectionAndExit(std::wstring(L"Overlay: ") + cls);
                return true;
            }
        }
        return false;
    }

    BOOL CALLBACK OverlayScanner::EnumWindowsThunk(HWND hwnd, LPARAM lParam) {
        auto self = reinterpret_cast<OverlayScanner*>(lParam);
        if (!IsWindowVisible(hwnd)) return TRUE;
        self->IsBlacklistedWindow(hwnd);
        return TRUE; // stop only via ShowDetectionAndExit (process exit)
    }

    void OverlayScanner::Tick() {
        EnumWindows(OverlayScanner::EnumWindowsThunk, reinterpret_cast<LPARAM>(this));
    }
}
