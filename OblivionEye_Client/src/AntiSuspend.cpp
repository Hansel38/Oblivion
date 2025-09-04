#include "../include/AntiSuspend.h"
#include <windows.h>
#include <thread>
#include <chrono>
#include <iostream>
#include "../include/Logger.h"
#include "../include/Config.h"

static bool antiSuspendRunning = false;
static HANDLE monitoredThread = nullptr; // real handle (duplicated) to the main anti-cheat thread
static std::thread antiSuspendThread;

// Helper to close handle safely
static void CloseHandleSafe(HANDLE &h) {
    if (h && h != INVALID_HANDLE_VALUE) {
        CloseHandle(h);
        h = nullptr;
    }
}

// Fungsi untuk memeriksa apakah thread masih aktif
bool IsThreadActive(HANDLE threadHandle) {
    if (!threadHandle || threadHandle == INVALID_HANDLE_VALUE) return false;
    // WaitForSingleObject dengan timeout 0: jika masih aktif status WAIT_TIMEOUT
    DWORD waitRes = WaitForSingleObject(threadHandle, 0);
    return waitRes == WAIT_TIMEOUT; // masih berjalan
}

// Watchdog sederhana – hanya pastikan thread target belum selesai / di-terminate.
// (Deteksi suspend agresif dihapus karena teknik sebelumnya menggunakan pseudo handle dan GetThreadContext
//  berpotensi tidak valid / menghasilkan false positive / crash di beberapa environment.)
void AntiSuspendWatchdog() {
    auto& cfg = Config::Get();
    Logger::Log(LOG_INFO, "Anti-Suspend Thread started");
    while (antiSuspendRunning) {
        try {
            if (monitoredThread) {
                if (!IsThreadActive(monitoredThread)) {
                    Logger::Log(LOG_DETECTED, "Monitored thread not active anymore (terminated)");
                    ExitProcess(0);
                }
            }
        } catch (...) {
            // Jangan biarkan exception mematikan proses tanpa log
            Logger::Log(LOG_ERROR, "Exception in AntiSuspendWatchdog loop (continuing)");
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(cfg.antiSuspendIntervalMs));
    }
    Logger::Log(LOG_INFO, "Anti-Suspend Thread stopped");
}

void StartAntiSuspendThread(HANDLE mainThreadHandle) {
    if (antiSuspendRunning) return;

    // Ubah pseudo handle menjadi real handle yang bisa dipakai thread lain.
    // mainThreadHandle yang diteruskan (GetCurrentThread dari thread utama anti-cheat) kemungkinan pseudo handle (-2).
    HANDLE duplicated = nullptr;
    if (!DuplicateHandle(GetCurrentProcess(),
                         mainThreadHandle,
                         GetCurrentProcess(),
                         &duplicated,
                         THREAD_QUERY_INFORMATION | SYNCHRONIZE, // hak minimum yang kita butuhkan sekarang
                         FALSE,
                         0)) {
        Logger::Log(LOG_WARNING, "Failed to duplicate main thread handle for Anti-Suspend (GetLastError=" + std::to_string(GetLastError()) + ")");
        return; // jangan mulai watchdog tanpa handle valid
    }

    monitoredThread = duplicated;
    antiSuspendRunning = true;
    antiSuspendThread = std::thread(AntiSuspendWatchdog);
}

void StopAntiSuspendThread() {
    if (!antiSuspendRunning) {
        CloseHandleSafe(monitoredThread);
        return;
    }
    antiSuspendRunning = false;
    if (antiSuspendThread.joinable()) antiSuspendThread.join();
    CloseHandleSafe(monitoredThread);
}