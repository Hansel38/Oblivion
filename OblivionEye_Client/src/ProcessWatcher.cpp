#include "../include/ProcessWatcher.h"
#include <windows.h>
#include <tlhelp32.h>
#include <algorithm>
#include <string>
#include <set>
#include <thread>
#include <chrono>
#include "../include/Blacklist.h"
#include "../include/Logger.h"
#include "../include/Config.h"
#include "../include/DetectionController.h"
#include "../include/SleepUtil.h"

// Set untuk menyimpan proses yang sudah discan (hanya untuk blacklist)
std::set<std::string> scannedBlacklistProcesses;

// Fungsi untuk scan semua proses yang sedang berjalan
bool ScanRunningProcesses() {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        Logger::Log(LOG_ERROR, "Failed to create process snapshot");
        return false;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);

    if (Process32First(hSnap, &pe)) {
        do {
            // Konversi WCHAR[] ke std::string menggunakan ws2s inline dari header
            std::string currentProcessName = ws2s(std::wstring(pe.szExeFile));
            std::string lowerProcessName = toLower(currentProcessName);

            // Hanya cek proses yang ada di blacklist (EKSKLUSIF)
            for (const auto& blacklisted : blacklistedProcesses) {
                std::string lowerBlacklisted = toLower(blacklisted);
                if (lowerProcessName == lowerBlacklisted) {
                    // Cek apakah proses ini sudah discan sebelumnya
                    if (scannedBlacklistProcesses.find(lowerProcessName) == scannedBlacklistProcesses.end()) {
                        // Tandai proses ini sudah discan
                        scannedBlacklistProcesses.insert(lowerProcessName);

                        // Log hanya proses blacklist yang ditemukan
                        Logger::Log(LOG_INFO, "BLACKLIST HIT - Scanning process: " + currentProcessName);

                        CloseHandle(hSnap);
                        DetectionController::ReportDetection(Config::Get().cheatDetectedPrefix + std::string(" ") + blacklisted);
                        MessageBoxA(NULL, ("Cheat Detected: " + blacklisted).c_str(), "Oblivion Eye", MB_ICONERROR);
                        return true; // Terdeteksi cheat
                    }
                }
            }
        } while (Process32Next(hSnap, &pe));
    }

    CloseHandle(hSnap);
    return false; // Tidak terdeteksi
}

// Fungsi untuk scanning continuous
void ContinuousProcessScan() {
    auto& cfg = Config::Get();
    Logger::Log(LOG_INFO, "Process Watcher started");

    SleepWithStopSeconds(cfg.processInitialDelaySec);
    if (DetectionController::IsStopRequested()) return;
    // Scan pertama kali saat startup
    if (ScanRunningProcesses()) return; // detection will signal stop

    // Scan terus-menerus setiap interval yang diatur dalam konfigurasi
    while (!DetectionController::IsStopRequested()) {
        SleepWithStopSeconds(cfg.processIntervalSec);
        if (DetectionController::IsStopRequested()) break;
        if (ScanRunningProcesses()) break;
    }

    Logger::Log(LOG_INFO, "Process Watcher thread exiting");
}