#include "../include/overlay_scanner.h"
#include <Windows.h>
#include <string>
#include <vector>

namespace OverlayScanner {
    // Daftar nama window yang mencurigakan
    const std::vector<std::wstring> SUSPICIOUS_WINDOW_NAMES = {
        L"DXOverlay",
        L"DXWindow",
        L"OverlayWindow",
        L"Trainer",
        L"ESP",
        L"Cheat",
        L"Hack",
        L"External",
        L"Overlay"
    };

    // Enumerasi callback untuk window
    BOOL CALLBACK EnumWindowsCallback(HWND hwnd, LPARAM lParam) {
        bool* found = reinterpret_cast<bool*>(lParam);
        if (*found) return FALSE; // Hentikan jika sudah menemukan

        // Dapatkan nama window
        wchar_t windowTitle[256];
        GetWindowTextW(hwnd, windowTitle, sizeof(windowTitle) / sizeof(windowTitle[0]));

        // Dapatkan class window
        wchar_t windowClass[256];
        GetClassNameW(hwnd, windowClass, sizeof(windowClass) / sizeof(windowClass[0]));

        // Cek apakah window berada di atas game
        HWND gameWindow = FindWindowW(L"ROClientClass", nullptr);
        if (gameWindow && IsWindowVisible(hwnd) && GetWindow(hwnd, GW_HWNDPREV) == gameWindow) {
            // Cek nama window
            std::wstring title(windowTitle);
            std::wstring cls(windowClass);

            for (const auto& suspicious : SUSPICIOUS_WINDOW_NAMES) {
                if (title.find(suspicious) != std::wstring::npos ||
                    cls.find(suspicious) != std::wstring::npos) {
                    *found = true;
                    return FALSE; // Hentikan enumerasi
                }
            }
        }
        return TRUE; // Lanjutkan enumerasi
    }

    bool DetectOverlayWindows() {
        bool foundOverlay = false;
        EnumWindows(EnumWindowsCallback, reinterpret_cast<LPARAM>(&foundOverlay));
        return foundOverlay;
    }
}