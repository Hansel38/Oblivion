#pragma once
#include <string>
#include <vector>
#include <windows.h>

// Struktur untuk menyimpan informasi IAT entry yang mencurigakan
struct SuspiciousIATEntry {
    std::string moduleName;       // Nama module yang memiliki IAT ini (misal: RRO.exe, mygame.dll)
    std::string importedModuleName; // Nama module yang diimpor (misal: kernel32.dll)
    std::string functionName;     // Nama fungsi yang diimpor (misal: VirtualAlloc)
    FARPROC originalAddress;      // Alamat asli fungsi dari module asli
    FARPROC currentAddress;       // Alamat yang sekarang ada di IAT (bisa berbeda jika di-hook)
    bool isHooked;                // Flag apakah entry ini dianggap hooked
};

// Deklarasi fungsi
std::vector<SuspiciousIATEntry> ScanModuleIAT(HMODULE hModule);
bool ScanAllModulesForIATHooks();
void ContinuousIATHookScan();