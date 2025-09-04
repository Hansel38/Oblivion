#include "../include/OverlayScanner.h"
#include <windows.h>
#include <string>
#include <vector>
#include <algorithm>
#include <thread>
#include <chrono>
#include "../include/Logger.h"
#include "../include/ProcessWatcher.h"
#include "../include/Config.h"
#include "../include/DetectionController.h"
#include "../include/SleepUtil.h"

static std::vector<std::string> scannedWindowTitles;

BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
    if (DetectionController::IsStopRequested()) return FALSE; // abort enumeration early
    auto& cfg = Config::Get();
    if (IsWindowVisible(hwnd)) {
        char windowTitle[256];
        GetWindowTextA(hwnd, windowTitle, sizeof(windowTitle));
        if (strlen(windowTitle) > 0) {
            std::string title(windowTitle);
            std::string lowerTitle = toLower(title);
            if ((int)title.length() > cfg.windowTitleMaxLength) return TRUE;
            bool alreadyScanned = false;
            for (const auto& scanned : scannedWindowTitles) {
                if (toLower(scanned) == lowerTitle) { alreadyScanned = true; break; }
            }
            if (!alreadyScanned) {
                scannedWindowTitles.push_back(title);
                for (const auto& suspicious : cfg.suspiciousWindowTitles) {
                    std::string lowerSuspicious = toLower(suspicious);
                    if (lowerTitle == lowerSuspicious || lowerTitle.find(lowerSuspicious) != std::string::npos) {
                        bool isSafe = false;
                        for (const auto& safeWord : cfg.overlaySafeWords) {
                            if (lowerTitle.find(toLower(safeWord)) != std::string::npos) { isSafe = true; break; }
                        }
                        if (!isSafe) {
                            Logger::Log(LOG_INFO, "Suspicious window detected: " + title);
                            DetectionController::ReportDetection(cfg.overlayDetectedPrefix + std::string(" ") + title);
                            MessageBoxA(NULL, ("Suspicious Window Detected: " + title).c_str(), "Oblivion Eye", MB_ICONERROR);
                            return FALSE; // stop enumeration
                        }
                    }
                }
            }
        }
    }
    return TRUE;
}

bool ScanOverlayWindows() {
    scannedWindowTitles.clear();
    return !EnumWindows(EnumWindowsProc, 0);
}

void ContinuousOverlayScan() {
    auto& cfg = Config::Get();
    Logger::Log(LOG_INFO, "Overlay Scanner started");
    SleepWithStopSeconds(cfg.overlayInitialDelaySec);
    if (DetectionController::IsStopRequested()) return;
    if (ScanOverlayWindows()) return; // detection triggered
    while (!DetectionController::IsStopRequested()) {
        SleepWithStopSeconds(cfg.overlayIntervalSec);
        if (DetectionController::IsStopRequested()) break;
        if (ScanOverlayWindows()) break;
    }
    Logger::Log(LOG_INFO, "Overlay Scanner thread exiting");
}