#include "../include/OverlayScanner.h"
#include "../include/Blacklist.h"
#include "../include/Logger.h"
#include <windows.h>
#include <algorithm>

// Callback untuk EnumWindows
BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
    bool* detected = reinterpret_cast<bool*>(lParam);

    // Cek apakah window visible
    if (!IsWindowVisible(hwnd))
        return TRUE;

    // Dapatkan panjang teks window
    int length = GetWindowTextLengthA(hwnd);
    if (length == 0)
        return TRUE;

    // Ambil teks window
    std::string windowTitle(length, 0);
    GetWindowTextA(hwnd, &windowTitle[0], length + 1);

    // Convert ke lowercase
    std::transform(windowTitle.begin(), windowTitle.end(), windowTitle.begin(), ::tolower);

    // Filter whitelist dulu (jika ada di whitelist, skip)
    for (const auto& safeName : WHITELISTED_WINDOWS) {
        if (windowTitle.find(safeName) != std::string::npos) {
            return TRUE; // Window aman, lanjut ke berikutnya
        }
    }

    // Cek apakah ada di blacklist
    for (const auto& name : OVERLAY_BLACKLIST) {
        if (windowTitle.find(name) != std::string::npos) {
            Logger::LogDetected("Overlay: " + windowTitle);
            *detected = true;
            return FALSE; // Stop enumeration
        }
    }

    return TRUE; // Lanjut ke window berikutnya
}

bool OverlayScanner::IsOverlayDetected() {
    bool detected = false;
    EnumWindows(EnumWindowsProc, reinterpret_cast<LPARAM>(&detected));
    return detected;
}