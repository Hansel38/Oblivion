#include "../include/anti_suspend.h"
#include <Windows.h>
#include <atomic>
#include <thread>
#include <chrono>

namespace AntiSuspend {
    // Variabel global untuk monitoring
    std::atomic<bool> monitoringActive(false);
    std::atomic<bool> isSuspended(false);
    ULONGLONG lastTickCount = 0;

    // Threshold untuk mendeteksi suspensi (dalam milidetik)
    const int SUSPENSION_THRESHOLD_MS = 100;
    const int CHECK_INTERVAL_MS = 50;

    // Fungsi untuk thread monitoring
    void MonitoringThread() {
        // Gunakan GetTickCount64() saja - lebih aman dan tidak menyebabkan konflik
        lastTickCount = GetTickCount64();

        while (monitoringActive) {
            ULONGLONG currentTime = GetTickCount64();

            // Hitung selisih waktu dalam milidetik
            ULONGLONG elapsedMs = currentTime - lastTickCount;

            // Jika waktu yang berlalu jauh lebih besar dari interval pemantauan
            if (lastTickCount != 0 && elapsedMs > SUSPENSION_THRESHOLD_MS) {
                isSuspended = true;
                break;
            }

            // Update tick terakhir
            lastTickCount = currentTime;

            // Tunggu sebentar sebelum cek berikutnya
            std::this_thread::sleep_for(std::chrono::milliseconds(CHECK_INTERVAL_MS));
        }
    }

    void InitializeThreadMonitoring() {
        // Reset status
        isSuspended = false;
        lastTickCount = 0;

        // Inisialisasi counter
        lastTickCount = GetTickCount64();

        // Mulai thread monitoring
        monitoringActive = true;
        std::thread(MonitoringThread).detach();
    }

    bool IsThreadSuspended() {
        return isSuspended;
    }

    void StopThreadMonitoring() {
        monitoringActive = false;
    }
}