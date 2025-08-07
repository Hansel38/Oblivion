#include "../include/OverlayScanner.h"
#include <windows.h>
#include <string>
#include <vector>
#include <algorithm>
#include <thread>
#include <chrono>
#include "../include/Logger.h"
#include "../include/ProcessWatcher.h"  // Untuk mengakses toLower

// Daftar judul window yang mencurigakan (blacklist) - LEBIH SPESIFIK
const std::vector<std::string> suspiciousWindowTitles = {
    "Cheat Engine",
    "CheatEngine",
    "ESP Hack",
    "Wallhack",
    "Aimbot",
    "TriggerBot",
    "Memory Editor",
    "Process Hacker",
    "x64_dbg",
    "x32_dbg",
    "OllyDbg",
    "IDA Pro",
    "IDA Freeware",
    "Game Hack",
    "Game Cheat",
    "RPE",
    "WPE",
    "WireShark",
    "Packet Editor",
    "DLL Injector",
    "Speed Hack",
    "Freeze Hack",
    "Cheat Tool"
    // Hapus kata-kata umum seperti "Overlay" yang bisa false positive
};

// Set untuk menyimpan window titles yang sudah discan
static std::vector<std::string> scannedWindowTitles;

// Fungsi callback untuk EnumWindows
BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
    // Cek apakah window terlihat
    if (IsWindowVisible(hwnd)) {
        char windowTitle[256];
        GetWindowTextA(hwnd, windowTitle, sizeof(windowTitle));

        if (strlen(windowTitle) > 0) {
            std::string title(windowTitle);
            std::string lowerTitle = toLower(title);

            // Abaikan window title yang terlalu panjang (biasanya bukan cheat)
            if (title.length() > 100) {
                return TRUE; // Lanjut enumerasi
            }

            // Cek apakah title ini sudah discan sebelumnya
            bool alreadyScanned = false;
            for (const auto& scanned : scannedWindowTitles) {
                if (toLower(scanned) == lowerTitle) {
                    alreadyScanned = true;
                    break;
                }
            }

            if (!alreadyScanned) {
                // Tambahkan ke daftar scanned
                scannedWindowTitles.push_back(title);

                // Cek apakah title mencurigakan - GUNAKAN PERBANDINGAN EXACT ATAU MATCH YANG LEBIH KUAT
                for (const auto& suspicious : suspiciousWindowTitles) {
                    std::string lowerSuspicious = toLower(suspicious);

                    // Cek exact match atau partial match yang lebih ketat
                    if (lowerTitle == lowerSuspicious ||
                        lowerTitle.find(lowerSuspicious) != std::string::npos) {

                        // Tambahkan pengecekan tambahan untuk menghindari false positive
                        // Jangan deteksi jika mengandung kata-kata normal
                        std::vector<std::string> safeWords = {
                            "google", "chrome", "firefox", "microsoft", "edge",
                            "shopee", "tokopedia", "whatsapp", "discord",
                            "notepad", "visual studio", "devenv", "explorer"
                        };

                        bool isSafe = false;
                        for (const auto& safeWord : safeWords) {
                            if (lowerTitle.find(safeWord) != std::string::npos) {
                                isSafe = true;
                                break;
                            }
                        }

                        if (!isSafe) {
                            Logger::Log(LOG_INFO, "Suspicious window detected: " + title);
                            Logger::Log(LOG_DETECTED, "Overlay/ESP hack detected: " + title);
                            MessageBoxA(NULL, ("Suspicious Window Detected: " + title).c_str(), "Oblivion Eye", MB_ICONERROR);

                            // Kirim signal untuk menutup client
                            PostThreadMessage(GetCurrentThreadId(), WM_QUIT, 0, 0);
                            return FALSE; // Hentikan enumerasi
                        }
                    }
                }
            }
        }
    }
    return TRUE; // Lanjut enumerasi
}

// Fungsi untuk scan semua window yang aktif
bool ScanOverlayWindows() {
    scannedWindowTitles.clear(); // Reset untuk scan baru
    return !EnumWindows(EnumWindowsProc, 0); // Return true jika terdeteksi (FALSE dari callback)
}

// Fungsi untuk scanning continuous
void ContinuousOverlayScan() {
    Logger::Log(LOG_INFO, "Overlay Scanner started");

    // Delay awal 10 detik
    std::this_thread::sleep_for(std::chrono::seconds(10));

    // Scan pertama kali saat startup
    if (ScanOverlayWindows()) {
        Logger::Log(LOG_DETECTED, "Overlay hack detected on startup, closing client");
        ExitProcess(0);
    }

    // Scan terus-menerus setiap 10 detik
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(10));
        if (ScanOverlayWindows()) {
            Logger::Log(LOG_DETECTED, "Overlay hack detected during runtime, closing client");
            ExitProcess(0);
        }
    }
}