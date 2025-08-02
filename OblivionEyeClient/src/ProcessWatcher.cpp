#include "../include/ProcessWatcher.h"
#include "../include/Blacklist.h"
#include "../include/Logger.h"
#include "../include/Utils.h" 
#include <algorithm>
#include <windows.h>

// Fungsi konversi aman di hapus pindah ke utils.h

bool ProcessWatcher::IsBlacklistedProcessRunning() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return false;

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (!Process32FirstW(hSnapshot, &pe32)) {
        CloseHandle(hSnapshot);
        return false;
    }

    // Tidak log scanning rutin, hanya log saat deteksi

    do {
        std::string processName = ws2s(std::wstring(pe32.szExeFile));
        std::transform(processName.begin(), processName.end(), processName.begin(), ::tolower);

        for (const auto& name : BLACKLISTED_PROCESSES) {
            if (processName.find(name) != std::string::npos) {
                Logger::LogDetected(processName); // Ini akan buka file log
                CloseHandle(hSnapshot);
                return true;
            }
        }
    } while (Process32NextW(hSnapshot, &pe32));

    // Tidak log "No cheats detected"
    CloseHandle(hSnapshot);
    return false;
}