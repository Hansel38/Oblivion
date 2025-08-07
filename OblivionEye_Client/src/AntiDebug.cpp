#include "../include/AntiDebug.h"
#include <windows.h>
#include <thread>
#include <chrono>
#include "../include/Logger.h"

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
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebuggerPresent)) {
        if (isDebuggerPresent) {
            Logger::Log(LOG_DETECTED, "CheckRemoteDebuggerPresent detected debugger");
            return true;
        }
    }
    return false;
}

// Fungsi utama untuk melakukan semua pengecekan anti-debug
bool PerformAntiDebugChecks() {
    // Hanya gunakan 2 metode yang sangat andal
    if (CheckIsDebuggerPresent()) return true;
    if (CheckRemoteDebugger()) return true;

    // Hapus timing check karena bisa menyebabkan false positive

    return false; // Tidak terdeteksi debugger
}

// Fungsi untuk scanning continuous
void ContinuousAntiDebugScan() {
    Logger::Log(LOG_INFO, "Anti-Debug Scanner started");

    // Delay awal 20 detik untuk menghindari deteksi saat startup
    std::this_thread::sleep_for(std::chrono::seconds(20));

    // Scan pertama kali saat startup
    if (PerformAntiDebugChecks()) {
        Logger::Log(LOG_DETECTED, "Debugger detected on startup, closing client");
        ExitProcess(0);
    }

    // Scan terus-menerus setiap 30 detik (sangat jarang untuk menghindari false positive)
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(30));

        if (PerformAntiDebugChecks()) {
            Logger::Log(LOG_DETECTED, "Debugger detected during runtime, closing client");
            ExitProcess(0);
        }
    }
}