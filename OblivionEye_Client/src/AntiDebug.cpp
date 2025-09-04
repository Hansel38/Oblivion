#include "../include/AntiDebug.h"
#include <windows.h>
#include <thread>
#include <chrono>
#include "../include/Logger.h"
#include "../include/Config.h"
#include "../include/DetectionController.h"
#include "../include/SleepUtil.h"

// Fungsi untuk deteksi debugger dasar
bool CheckIsDebuggerPresent() {
    if (IsDebuggerPresent()) {
        Logger::Log(LOG_DETECTED, "IsDebuggerPresent detected debugger");
        return true;
    }
    return false;
}

// Fungsi untuk deteksi debugger remote
bool CheckRemoteDebugger() {
    BOOL isDebuggerPresent = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebuggerPresent) && isDebuggerPresent) {
        Logger::Log(LOG_DETECTED, "CheckRemoteDebuggerPresent detected debugger");
        return true;
    }
    return false;
}

// Fungsi utama untuk melakukan semua pengecekan anti-debug
bool PerformAntiDebugChecks() {
    // Hanya gunakan 2 metode yang sangat andal
    if (CheckIsDebuggerPresent()) return true;
    if (CheckRemoteDebugger()) return true;

    return false; // Tidak terdeteksi debugger
}

// Fungsi untuk scanning continuous
void ContinuousAntiDebugScan() {
    auto& cfg = Config::Get();
    Logger::Log(LOG_INFO, "Anti-Debug Scanner started");

    SleepWithStopSeconds(cfg.antiDebugInitialDelaySec);
    if (DetectionController::IsStopRequested()) return;

    // Scan pertama kali saat startup
    if (PerformAntiDebugChecks()) {
        DetectionController::ReportDetection("Debugger detected at startup");
        return;
    }

    // Scan terus-menerus setiap 30 detik (sangat jarang untuk menghindari false positive)
    while (!DetectionController::IsStopRequested()) {
        SleepWithStopSeconds(cfg.antiDebugIntervalSec);
        if (DetectionController::IsStopRequested()) break;

        if (PerformAntiDebugChecks()) {
            DetectionController::ReportDetection("Debugger detected during runtime");
            break;
        }
    }

    Logger::Log(LOG_INFO, "Anti-Debug Scanner thread exiting");
}