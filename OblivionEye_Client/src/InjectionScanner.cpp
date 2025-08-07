#include "../include/InjectionScanner.h"
#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <vector>
#include <algorithm>
#include <thread>
#include <chrono>
#include <set>
#include <shlwapi.h> // Untuk PathMatchSpecA, PathFindFileNameA
#include <psapi.h>   // Untuk GetModuleFileNameExA
#include "../include/Logger.h"
#include "../include/ProcessWatcher.h" // Untuk toLower dan ws2s

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "psapi.lib")

// Set untuk menyimpan DLL yang sudah discan
static std::set<std::string> scannedModules;

// --- TAMBAHKAN BAGIAN INI ---
// Daftar nama dasar DLL yang SELALU diizinkan (whitelisted).
const std::vector<std::string> baseWhitelistedNames = {
    // Windows System DLLs (Common)
    "ntdll", "kernel32", "kernelbase", "user32", "gdi32", "gdi32full", "advapi32",
    "shell32", "ole32", "oleaut32", "comctl32", "comdlg32", "shlwapi", "msvcrt",
    "ucrtbase", "vcruntime140", "msvcp140", "winmm", "ws2_32", "iphlpapi", "version",
    "crypt32", "wininet", "urlmon", "oleacc", "propsys", "uxtheme", "dwmapi",
    "dxgi", "d3d11", "d3d9", "opengl32", "dsound", "dinput8", "wintrust", "imagehlp",
    "sechost", "bcrypt", "rpcrt4", "combase", "imm32", "msctf", "cryptsp", "powrprof",
    "shcore", "cfgmgr32", "devobj", "setupapi", "bcryptprimitives", "msasn1",
    "win32u", "gdiplus", "ddraw", "dciman32", "dxcore", "windows.storage",
    "coremessaging", "textinputframework", "wldap32", "dnsapi", "netapi32",

    // MSVC Runtime DLLs
    "msvcr120", "msvcp120", "msvcr140", "msvcp140", "vcruntime140",
    "msvcp140d", "vcruntime140d", "ucrtbased", "msvcr110",

    // API Sets (Pattern-based di bawah sudah menangani ini, tapi sertakan beberapa umum)
    "api-ms-win-core",
    "api-ms-win-crt",

    // Game-related DLLs (Umum)
    "granny2", "binkw32", "ijl15", "mss32", "libcurl", "nvldumd", "nvd3dum",
    "openal32", "fmod", "sdl2",

    // DLL Kita Sendiri
    "oblivioneye_client", "rro"
};

// Daftar pola awalan untuk API Sets dan DLL sistem lainnya yang dinamis
const std::vector<std::string> systemPatterns = {
    "api-ms-win-", "ext-ms-win-", "wow64", "profapi", "appmodel", "samcli",
    "srvcli", "wkscli", "logoncli", "cabinet", "hid", "winusb", "usbapi",
    "dhcpcsvc", "dhcpcsvc6", "rasapi32", "rtutils", "sensapi", "ncrypt",
    "ntasn1", "winspool", "mpr", "cryptnet", "gpapi", "cryptbase", "rsaenh",
    "mswsock", "napinsp", "pnrpnsp", "winrnr", "wshbth", "nlansp_c", "fwpuclnt",
    "rasadhlp", "avrt", "t2embed", "dwrite", "d2d1", "d3dcompiler", "resourcepolicyclient",
    "windows.ui", "coreui", "coremessaging", "wintypes", "resampledmo", "winmmbase",
    "msdmo", "umpdc", "clbcatq", "mmdevapi", "audioses", "netutils", "kernel.appcore"
};
// --- AKHIR TAMBAHAN ---

// --- TAMBAHKAN FUNGSI INI ---
// Fungsi untuk memeriksa apakah path DLL berada di direktori sistem Windows
bool IsSystemDirectoryPath(const std::string& fullPath) {
    // Daftar direktori sistem umum
    const std::vector<std::string> systemDirs = {
        "C:\\Windows\\System32\\",
        "C:\\Windows\\SysWOW64\\",
        "C:\\Windows\\WinSxS\\"
    };

    std::string lowerPath = toLower(fullPath);
    for (const auto& sysDir : systemDirs) {
        // Periksa apakah path dimulai dengan direktori sistem
        if (lowerPath.find(toLower(sysDir)) == 0) {
            return true;
        }
    }
    return false;
}
// --- AKHIR TAMBAHAN FUNGSI ---

// Fungsi untuk memeriksa apakah DLL ada di whitelist
bool IsDLLWhitelisted(const std::string& dllName, const std::string& fullPath) {
    // --- TAMBAHKAN PENGECEKAN INI ---
    // 1. Cek apakah DLL berasal dari direktori sistem Windows
    // Jika iya, anggap aman tanpa perlu pengecekan lebih lanjut
    if (IsSystemDirectoryPath(fullPath)) {
        Logger::Log(LOG_INFO, "Skipped system DLL: " + dllName + " (Path: " + fullPath + ")");
        return true; // LEWATI DLL SISTEM
    }
    // --- AKHIR PENGECEKAN ---

    std::string lowerDllName = toLower(dllName);

    // 2. Cek ekstensi file umum yang biasanya aman (game-related)
    const std::vector<std::string> safeExtensions = { ".asi", ".m3d", ".flt", ".mix", ".dll" };
    bool hasSafeExt = false;
    for (const auto& ext : safeExtensions) {
        if (lowerDllName.length() >= ext.length() &&
            lowerDllName.compare(lowerDllName.length() - ext.length(), ext.length(), ext) == 0) {
            hasSafeExt = true;
            if (ext == ".asi" || ext == ".m3d") {
                Logger::Log(LOG_INFO, "Whitelisted (Safe Extension): " + dllName);
                return true;
            }
            break;
        }
    }

    if (!hasSafeExt) {
        Logger::Log(LOG_INFO, "Unknown Extension, checking name: " + dllName);
    }

    // 3. Cek nama dasar (tanpa ekstensi .dll)
    std::string baseName = lowerDllName;
    size_t dotPos = lowerDllName.find_last_of('.');
    if (dotPos != std::string::npos && dotPos > 0) {
        baseName = lowerDllName.substr(0, dotPos);
    }

    // 4. Cocokkan dengan daftar nama dasar yang diizinkan
    for (const auto& whitelistedBase : baseWhitelistedNames) {
        if (baseName == toLower(whitelistedBase)) {
            Logger::Log(LOG_INFO, "Whitelisted (Base Name Match): " + dllName);
            return true;
        }
    }

    // 5. Cocokkan dengan pola sistem
    for (const auto& pattern : systemPatterns) {
        if (lowerDllName.find(pattern) != std::string::npos) {
            Logger::Log(LOG_INFO, "Whitelisted (Pattern Match): " + dllName);
            return true;
        }
    }

    // 6. Jika sampai sini, belum ditemukan di whitelist
    Logger::Log(LOG_INFO, "Not Whitelisted, will check if suspicious: " + dllName);
    return false;
}


// Fungsi untuk scan semua module yang dimuat
bool ScanInjectedDLLs() {
    scannedModules.clear();

    HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    if (hModuleSnap == INVALID_HANDLE_VALUE) {
        Logger::Log(LOG_ERROR, "Failed to create module snapshot");
        return false;
    }

    MODULEENTRY32 me32;
    me32.dwSize = sizeof(MODULEENTRY32);

    if (!Module32First(hModuleSnap, &me32)) {
        DWORD lastError = GetLastError();
        CloseHandle(hModuleSnap);
        Logger::Log(LOG_ERROR, "Failed to get first module. Error: " + std::to_string(lastError));
        return false;
    }

    bool injectedDLLDetected = false;
    int suspiciousCount = 0;

    do {
        // Konversi nama module dan path ke string
        std::string moduleName = ws2s(std::wstring(me32.szModule));
        std::string modulePath = ws2s(std::wstring(me32.szExePath)); // TAMBAHKAN INI
        std::string lowerModuleName = toLower(moduleName);

        if (scannedModules.find(lowerModuleName) == scannedModules.end()) {
            scannedModules.insert(lowerModuleName);

            // --- UPDATE INI: KIRIM DUA PARAMETER ---
            if (!IsDLLWhitelisted(moduleName, modulePath)) {
                // --- SISANYA KODE TETAP SAMA ---
                const std::vector<std::string> verySafePatterns = {
                    "rro.exe", "ntdll.dll", "kernel32.dll", "user32.dll", "gdi32.dll",
                    "msvcr", "msvcp", "vcruntime", "ucrtbase", "api-ms-win", "ext-ms-win"
                };

                bool isVerySafe = false;
                for (const auto& pattern : verySafePatterns) {
                    if (lowerModuleName.find(pattern) != std::string::npos) {
                        isVerySafe = true;
                        Logger::Log(LOG_INFO, "Very Safe Pattern, Ignoring: " + moduleName);
                        break;
                    }
                }

                if (!isVerySafe) {
                    Logger::Log(LOG_DETECTED, "Suspicious DLL detected: " + moduleName);
                    suspiciousCount++;
                    if (suspiciousCount > 2) {
                        Logger::Log(LOG_INFO, "More than 2 suspicious DLLs, flagging as injected.");
                        injectedDLLDetected = true;
                    }
                }
            }
        }
    } while (Module32Next(hModuleSnap, &me32));

    CloseHandle(hModuleSnap);

    if (suspiciousCount > 0 && suspiciousCount <= 2) {
        Logger::Log(LOG_INFO, "Only " + std::to_string(suspiciousCount) + " suspicious modules, likely false positives. Ignoring.");
        return false;
    }

    return injectedDLLDetected;
}

// Fungsi untuk scanning continuous
void ContinuousInjectionScan() {
    Logger::Log(LOG_INFO, "Injection Scanner started");

    std::this_thread::sleep_for(std::chrono::seconds(30));

    if (ScanInjectedDLLs()) {
        Logger::Log(LOG_DETECTED, "Injected DLL detected on startup, closing client");
        ExitProcess(0);
    }

    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(60));
        if (ScanInjectedDLLs()) {
            Logger::Log(LOG_DETECTED, "Injected DLL detected during runtime, closing client");
            ExitProcess(0);
        }
    }
}