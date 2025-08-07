#include "../include/AntiSuspend.h"
#include <windows.h>
#include <thread>
#include <chrono>
#include <iostream>
#include "../include/Logger.h"

static bool antiSuspendRunning = false;
static HANDLE monitoredThread = nullptr;
static std::thread antiSuspendThread;

// Fungsi untuk memeriksa apakah thread masih aktif
bool IsThreadActive(HANDLE threadHandle) {
    if (threadHandle == nullptr || threadHandle == INVALID_HANDLE_VALUE) {
        return false;
    }

    // Dapatkan status thread
    DWORD exitCode = 0;
    if (GetExitCodeThread(threadHandle, &exitCode)) {
        // Jika thread masih berjalan, exit code adalah STILL_ACTIVE
        if (exitCode == STILL_ACTIVE) {
            return true;
        }
    }

    return false;
}

// Fungsi untuk memeriksa apakah thread di-suspend
bool IsThreadSuspended(HANDLE threadHandle) {
    if (threadHandle == nullptr || threadHandle == INVALID_HANDLE_VALUE) {
        return true; // Dianggap suspended jika handle tidak valid
    }

    // Coba dapatkan context thread
    CONTEXT context;
    context.ContextFlags = CONTEXT_CONTROL;

    // Jika tidak bisa mendapatkan context, kemungkinan thread di-suspend
    if (!GetThreadContext(threadHandle, &context)) {
        DWORD lastError = GetLastError();
        // ERROR_ACCESS_DENIED atau ERROR_INVALID_PARAMETER bisa menunjukkan thread suspended
        if (lastError == ERROR_ACCESS_DENIED || lastError == ERROR_INVALID_PARAMETER) {
            return true;
        }
    }

    return false;
}

// Fungsi watchdog untuk memantau thread
void AntiSuspendWatchdog() {
    Logger::Log(LOG_INFO, "Anti-Suspend Thread started");

    while (antiSuspendRunning) {
        if (monitoredThread != nullptr) {
            // Cek apakah thread masih aktif
            if (!IsThreadActive(monitoredThread)) {
                Logger::Log(LOG_DETECTED, "Monitored thread is not active");
                ExitProcess(0);
            }

            // Cek apakah thread di-suspend
            if (IsThreadSuspended(monitoredThread)) {
                Logger::Log(LOG_DETECTED, "Thread suspension detected - possible anti-cheat bypass attempt");
                ExitProcess(0);
            }
        }

        // Tidur sebentar untuk menghindari penggunaan CPU berlebih
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }

    Logger::Log(LOG_INFO, "Anti-Suspend Thread stopped");
}

// Fungsi untuk memulai thread anti-suspend
void StartAntiSuspendThread(HANDLE mainThreadHandle) {
    if (antiSuspendRunning) {
        return; // Sudah berjalan
    }

    monitoredThread = mainThreadHandle;
    antiSuspendRunning = true;

    // Buat thread watchdog
    antiSuspendThread = std::thread(AntiSuspendWatchdog);

    // Detach thread agar bisa berjalan independen
    // Tapi kita simpan handle untuk kontrol lebih lanjut
    if (antiSuspendThread.joinable()) {
        // Jangan detach dulu, kita butuh kontrol
    }
}

// Fungsi untuk menghentikan thread anti-suspend
void StopAntiSuspendThread() {
    if (antiSuspendRunning) {
        antiSuspendRunning = false;

        // Tunggu thread selesai
        if (antiSuspendThread.joinable()) {
            antiSuspendThread.join();
        }
    }
}