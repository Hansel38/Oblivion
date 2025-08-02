#include "../include/InjectionScanner.h"
#include "../include/Blacklist.h"
#include "../include/Logger.h"
#include "../include/Utils.h" 
#include <windows.h>
#include <tlhelp32.h>
#include <algorithm>

// Fungsi konversi aman di hapus pindah ke utils.h


bool InjectionScanner::IsInjectedDllDetected() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return false;

    MODULEENTRY32W me32; // Gunakan versi Unicode
    me32.dwSize = sizeof(MODULEENTRY32W);

    if (!Module32FirstW(hSnapshot, &me32)) { //  Unicode
        CloseHandle(hSnapshot);
        return false;
    }

    do {
        // Konversi WCHAR ke std::string
        std::string moduleName = ws2s(std::wstring(me32.szModule));
        std::transform(moduleName.begin(), moduleName.end(), moduleName.begin(), ::tolower);

        // Cek apakah ada di blacklist
        for (const auto& name : DLL_BLACKLIST) {
            std::string lowerName = name;
            std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);
            if (moduleName.find(lowerName) != std::string::npos) {
                Logger::LogDetected("Injected DLL: " + moduleName);
                CloseHandle(hSnapshot);
                return true;
            }
        }
    } while (Module32NextW(hSnapshot, &me32)); //  Unicode

    CloseHandle(hSnapshot);
    return false;
}