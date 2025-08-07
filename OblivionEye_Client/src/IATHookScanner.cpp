#include "../include/IATHookScanner.h"
#include <windows.h>
#include <psapi.h> // Untuk EnumProcessModules, GetModuleFileNameEx
#include <imagehlp.h> // Untuk ImageDirectoryEntryToData, ImageRvaToVa
#include <vector>
#include <set>
#include <thread>
#include <chrono>
#include <algorithm>
#include "../include/Logger.h"
#include "../include/ProcessWatcher.h" // Untuk ws2s

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "imagehlp.lib")

// Fungsi untuk mendapatkan nama module dari HMODULE
std::string GetModuleName(HMODULE hModule) {
    char moduleName[MAX_PATH];
    if (GetModuleFileNameExA(GetCurrentProcess(), hModule, moduleName, MAX_PATH)) {
        // Kembalikan hanya nama file, bukan path lengkap
        std::string fullPath(moduleName);
        size_t lastSlash = fullPath.find_last_of("\\/");
        if (lastSlash != std::string::npos) {
            return fullPath.substr(lastSlash + 1);
        }
        return fullPath;
    }
    return "UnknownModule";
}

// Fungsi untuk mendapatkan daftar semua module dalam proses
std::vector<HMODULE> GetAllProcessModules() {
    std::vector<HMODULE> modules;
    HANDLE hProcess = GetCurrentProcess();
    HMODULE hMods[1024];
    DWORD cbNeeded;

    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        DWORD numMods = cbNeeded / sizeof(HMODULE);
        for (DWORD i = 0; i < numMods; i++) {
            modules.push_back(hMods[i]);
        }
    }
    return modules;
}

// Fungsi untuk memeriksa apakah alamat berada dalam module yang dikenal
bool IsAddressInKnownModule(FARPROC address, const std::vector<HMODULE>& knownModules) {
    for (const auto& hMod : knownModules) {
        MODULEINFO modInfo;
        if (GetModuleInformation(GetCurrentProcess(), hMod, &modInfo, sizeof(modInfo))) {
            uintptr_t addr = (uintptr_t)address;
            uintptr_t modBase = (uintptr_t)modInfo.lpBaseOfDll;
            uintptr_t modEnd = modBase + modInfo.SizeOfImage;

            if (addr >= modBase && addr < modEnd) {
                return true;
            }
        }
    }
    return false;
}

// Fungsi untuk mendapatkan nama module dari alamat
std::string GetModuleNameFromAddress(FARPROC address, const std::vector<HMODULE>& knownModules) {
    for (const auto& hMod : knownModules) {
        MODULEINFO modInfo;
        if (GetModuleInformation(GetCurrentProcess(), hMod, &modInfo, sizeof(modInfo))) {
            uintptr_t addr = (uintptr_t)address;
            uintptr_t modBase = (uintptr_t)modInfo.lpBaseOfDll;
            uintptr_t modEnd = modBase + modInfo.SizeOfImage;

            if (addr >= modBase && addr < modEnd) {
                return GetModuleName(hMod);
            }
        }
    }
    return "Unknown";
}

// Fungsi untuk memindai IAT dari satu module
std::vector<SuspiciousIATEntry> ScanModuleIAT(HMODULE hModule) {
    std::vector<SuspiciousIATEntry> suspiciousEntries;
    HANDLE hProcess = GetCurrentProcess();
    std::string moduleName = GetModuleName(hModule);

    // Dapatkan daftar semua module untuk referensi
    auto allModules = GetAllProcessModules();

    // Dapatkan header PE
    ULONG size;
    IMAGE_IMPORT_DESCRIPTOR* iid = (IMAGE_IMPORT_DESCRIPTOR*)ImageDirectoryEntryToData(
        hModule, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &size);

    if (!iid) {
        // Module mungkin tidak memiliki IAT (unusual, tapi bisa terjadi)
        Logger::Log(LOG_INFO, "Module " + moduleName + " has no IAT or failed to read.");
        return suspiciousEntries;
    }

    // Iterasi melalui setiap entry dalam IAT
    while (iid->Name) {
        // Dapatkan nama module yang diimpor (misal: kernel32.dll)
        char* importedModuleName = (char*)ImageRvaToVa(
            (PIMAGE_NT_HEADERS)((BYTE*)hModule + ((PIMAGE_DOS_HEADER)hModule)->e_lfanew),
            hModule, iid->Name, NULL);

        if (!importedModuleName) {
            iid++;
            continue;
        }

        std::string importedModName(importedModuleName);
        std::transform(importedModName.begin(), importedModName.end(), importedModName.begin(), ::tolower);

        // Dapatkan thunk data (alamat fungsi)
        IMAGE_THUNK_DATA* oft = (IMAGE_THUNK_DATA*)ImageRvaToVa(
            (PIMAGE_NT_HEADERS)((BYTE*)hModule + ((PIMAGE_DOS_HEADER)hModule)->e_lfanew),
            hModule, iid->OriginalFirstThunk, NULL);
        IMAGE_THUNK_DATA* ft = (IMAGE_THUNK_DATA*)ImageRvaToVa(
            (PIMAGE_NT_HEADERS)((BYTE*)hModule + ((PIMAGE_DOS_HEADER)hModule)->e_lfanew),
            hModule, iid->FirstThunk, NULL);

        if (!oft || !ft) {
            iid++;
            continue;
        }

        // Iterasi melalui setiap fungsi yang diimpor
        while (oft->u1.AddressOfData) {
            // Dapatkan nama fungsi
            std::string functionName = "UnknownFunction";
            if (!(oft->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                IMAGE_IMPORT_BY_NAME* iibn = (IMAGE_IMPORT_BY_NAME*)ImageRvaToVa(
                    (PIMAGE_NT_HEADERS)((BYTE*)hModule + ((PIMAGE_DOS_HEADER)hModule)->e_lfanew),
                    hModule, oft->u1.AddressOfData, NULL);
                if (iibn) {
                    functionName = std::string((char*)iibn->Name);
                }
            }
            else {
                // Import by ordinal
                functionName = "Ordinal_" + std::to_string(IMAGE_ORDINAL(oft->u1.Ordinal));
            }

            // Dapatkan alamat fungsi saat ini di IAT (bisa sudah di-hook)
            FARPROC currentAddress = (FARPROC)ft->u1.Function;

            // Dapatkan alamat asli (ini kompleks, kita asumsikan jika alamat tidak dalam module yang benar, itu di-hook)
            // Untuk deteksi sederhana, kita hanya cek apakah alamat berada dalam module yang benar

            // Cek apakah alamat saat ini berada dalam module yang seharusnya (importedModuleName)
            HMODULE hExpectedModule = GetModuleHandleA(importedModuleName);
            bool isHooked = false;
            std::string hookedModuleName = "Unknown";

            if (hExpectedModule) {
                MODULEINFO expectedModInfo;
                if (GetModuleInformation(hProcess, hExpectedModule, &expectedModInfo, sizeof(expectedModInfo))) {
                    uintptr_t addr = (uintptr_t)currentAddress;
                    uintptr_t modBase = (uintptr_t)expectedModInfo.lpBaseOfDll;
                    uintptr_t modEnd = modBase + expectedModInfo.SizeOfImage;

                    if (addr < modBase || addr >= modEnd) {
                        // Alamat tidak berada dalam module yang seharusnya, kemungkinan besar di-hook
                        isHooked = true;
                        hookedModuleName = GetModuleNameFromAddress(currentAddress, allModules);
                    }
                }
            }
            else {
                // Module yang diimpor tidak ditemukan, ini juga mencurigakan
                isHooked = true;
                hookedModuleName = GetModuleNameFromAddress(currentAddress, allModules);
            }

            // Jika di-hook, catat
            if (isHooked) {
                SuspiciousIATEntry entry;
                entry.moduleName = moduleName;
                entry.importedModuleName = importedModName;
                entry.functionName = functionName;
                entry.originalAddress = nullptr; // Kita tidak punya cara mudah untuk mendapatkan ini
                entry.currentAddress = currentAddress;
                entry.isHooked = true;

                suspiciousEntries.push_back(entry);

                Logger::Log(LOG_DETECTED, "IAT Hook Detected! Module: " + moduleName +
                    " imports " + functionName + " from " + importedModName +
                    " but points to address 0x" + std::to_string((uintptr_t)currentAddress) +
                    " in module " + hookedModuleName);
            }

            oft++;
            ft++;
        }
        iid++;
    }

    return suspiciousEntries;
}

// Fungsi utama untuk memindai semua module
bool ScanAllModulesForIATHooks() {
    auto modules = GetAllProcessModules();
    bool hooksDetected = false;
    int totalHooks = 0;

    Logger::Log(LOG_INFO, "Starting IAT Hook scan for " + std::to_string(modules.size()) + " modules...");

    for (const auto& hMod : modules) {
        std::string modName = GetModuleName(hMod);

        // Abaikan module sistem dasar untuk mengurangi noise (opsional)
        std::vector<std::string> systemModules = {
            "ntdll.dll", "kernel32.dll", "kernelbase.dll", "user32.dll",
            "gdi32.dll", "advapi32.dll", "shell32.dll"
        };

        bool isSystemModule = false;
        std::string lowerModName = toLower(modName);
        for (const auto& sysMod : systemModules) {
            if (lowerModName == sysMod) {
                isSystemModule = true;
                break;
            }
        }

        // Scan semua module, termasuk sistem, untuk deteksi yang lebih komprehensif
        // Tapi bisa ditambahkan filter jika terlalu banyak false positive
        auto suspiciousEntries = ScanModuleIAT(hMod);

        if (!suspiciousEntries.empty()) {
            totalHooks += suspiciousEntries.size();
            hooksDetected = true;
            // Untuk demo, kita tidak return true langsung agar semua module discan
            // Tapi bisa diaktifkan jika ingin deteksi cepat
            // return true;
        }
    }

    if (hooksDetected) {
        Logger::Log(LOG_INFO, "IAT Hook scan completed. Total suspicious hooks found: " + std::to_string(totalHooks));
    }
    else {
        Logger::Log(LOG_INFO, "IAT Hook scan completed. No hooks detected.");
    }

    return hooksDetected;
}

// Fungsi untuk scanning continuous
void ContinuousIATHookScan() {
    Logger::Log(LOG_INFO, "IAT Hook Scanner started");

    // Delay awal 90 detik untuk memastikan semua module dimuat dan stabil
    std::this_thread::sleep_for(std::chrono::seconds(90));

    // Scan pertama kali saat startup
    if (ScanAllModulesForIATHooks()) {
        Logger::Log(LOG_DETECTED, "IAT hooks detected on startup, closing client");
        ExitProcess(0);
    }

    // Scan terus-menerus setiap 180 detik (3 menit - cukup jarang)
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(180));
        if (ScanAllModulesForIATHooks()) {
            Logger::Log(LOG_DETECTED, "IAT hooks detected during runtime, closing client");
            ExitProcess(0);
        }
    }
}