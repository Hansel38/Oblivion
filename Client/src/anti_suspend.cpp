#include "../include/anti_suspend.h"
#include <Windows.h>
#include <atomic>
#include <thread>
#include <chrono>

namespace AntiSuspend {
    // Variabel global untuk monitoring
    std::atomic<bool> monitoringActive(false);
    std::atomic<bool> isSuspended(false);
    LONGLONG lastTickCount = 0;
    LARGE_INTEGER frequency;

    // Threshold untuk mendeteksi suspensi (dalam milidetik)
    const int SUSPENSION_THRESHOLD_MS = 100;

    // Fungsi untuk thread monitoring
    void MonitoringThread() {
        // Dapatkan frekuensi counter performa tinggi
        QueryPerformanceFrequency(&frequency);

        while (monitoringActive) {
            LARGE_INTEGER currentTime;
            QueryPerformanceCounter(&currentTime);

            // Hitung selisih waktu dalam milidetik
            LONGLONG elapsedMs = ((currentTime.QuadPart - lastTickCount) * 1000) / frequency.QuadPart;

            // Jika waktu yang berlalu jauh lebih besar dari interval pemantauan
            if (lastTickCount != 0 && elapsedMs > SUSPENSION_THRESHOLD_MS) {
                isSuspended = true;
                break;
            }

            // Update tick terakhir
            lastTickCount = currentTime.QuadPart;

            // Tunggu sebentar sebelum cek berikutnya
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }

    void InitializeThreadMonitoring() {
        // Reset status
        isSuspended = false;
        lastTickCount = 0;

        // Inisialisasi counter performa
        LARGE_INTEGER currentTime;
        QueryPerformanceCounter(&currentTime);
        lastTickCount = currentTime.QuadPart;

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