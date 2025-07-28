#include "../include/injection_scanner.h"
#include <Windows.h>
#include <TlHelp32.h>
#include <vector>
#include <string>
#include <algorithm>
#include <cctype>
#include <Psapi.h>
#include <Shlwapi.h>

#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "Shlwapi.lib")

namespace InjectionScanner {
    // Daftar modul sistem yang diizinkan
    const std::vector<std::wstring> SYSTEM_MODULES = {
        L"ntdll.dll",
        L"kernel32.dll",
        L"kernelbase.dll",
        L"user32.dll",
        L"gdi32.dll",
        L"wininet.dll",
        L"ws2_32.dll",
        L"advapi32.dll",
        L"msvcrt.dll",
        L"version.dll",
        L"ole32.dll",
        L"oleaut32.dll",
        L"comdlg32.dll",
        L"shell32.dll",
        L"shlwapi.dll",
        L"imm32.dll",
        L"msctf.dll",
        L"rpcrt4.dll",
        L"sechost.dll",
        L"bcrypt.dll",
        L"crypt32.dll",
        L"uxtheme.dll",
        L"dwmapi.dll",
        L"winmm.dll",
        L"comctl32.dll",
        L"msvcp_win.dll",
        L"vcruntime140.dll",
        L"vcruntime140_1.dll",
        L"msvcp140.dll",
        L"msvcp140_1.dll",
        L"msvcp140_atomic_wait.dll",
        L"ucrtbase.dll",
        L"api-ms-win-*.dll",
        L"ext-ms-*.dll"
    };

    // Daftar modul game yang diizinkan
    const std::vector<std::wstring> GAME_MODULES = {
        L"rro.exe",
        L"oblivioneye.dll",
        L"d3d9.dll",
        L"d3d11.dll",
        L"d3d12.dll",
        L"d3dcompiler_47.dll",
        L"dxgi.dll",
        L"openal32.dll",
        L"openal64.dll",
        L"steam_api.dll",
        L"steam_api64.dll",
        L"steamclient.dll",
        L"steamclient64.dll",
        L"gameoverlayrenderer32.dll",
        L"gameoverlayrenderer64.dll",
        L"amd_ags_x64.dll",
        L"nvapi64.dll",
        L"atiuxp64.dll",
        L"atiu9p64.dll",
        L"ig9icd64.dll",
        L"ftlib64.dll",
        L"ftlib32.dll",
        L"ftgl64.dll",
        L"ftgl32.dll",
        L"dxcore.dll",
        L"dxil.dll",
        L"dxcompiler.dll",
        L"dxilconv.dll",
        L"dxilshadertracing.dll",
        L"ftkgl64.dll",
        L"ftkgl32.dll"
    };

    // Daftar modul keamanan yang diizinkan
    const std::vector<std::wstring> SECURITY_MODULES = {
        L"avgrs.exe",         // AVG
        L"avgnt.exe",        // AVG
        L"mbamservice.exe",  // Malwarebytes
        L"mbamtray.exe",     // Malwarebytes
        L"MsMpEng.exe",      // Windows Defender
        L"MsSense.exe",      // Windows Defender Advanced Threat Protection
        L"ccSvcHst.exe",     // Norton
        L"ccSetMgr.exe",     // Norton
        L"ccRegVfy.exe",     // Norton
        L"ekrn.exe",         // ESET
        L"egui.exe",         // ESET
        L"mcshield.exe",     // McAfee
        L"mfevtps.exe",      // McAfee
        L"mcafeefire.exe",   // McAfee
        L"nod32krn.exe",     // NOD32
        L"nod32kcs.exe",     // NOD32
        L"bdagent.exe",      // Bitdefender
        L"vsserv.exe",       // Kaspersky
        L"avp.exe",          // Kaspersky
        L"avpui.exe",        // Kaspersky
        L"avgwdsvc.exe",     // AVG
        L"avgidsagent.exe",  // AVG
        L"avgntflt.sys",     // AVG
        L"avgtpx86.sys",     // AVG
        L"avgtpx64.sys",     // AVG
        L"mbam.exe",         // Malwarebytes
        L"mbamgui.exe",      // Malwarebytes
        L"mbamscheduler.exe",// Malwarebytes
        L"mbamhealthservice.exe", // Malwarebytes
        L"MsMpEng.exe",      // Windows Defender
        L"SecurityHealthService.exe", // Windows Security
        L"SecurityHealthSystray.exe"  // Windows Security
    };

    // Daftar overlay yang diizinkan (seperti overlay game resmi)
    const std::vector<std::wstring> LEGITIMATE_OVERLAYS = {
        L"gameoverlayrenderer32.dll",
        L"gameoverlayrenderer64.dll",
        L"bho_base.dll",
        L"discord_overlay.dll",
        L"nvoglv64.dll",     // NVIDIA overlay
        L"nvoglv32.dll"      // NVIDIA overlay
    };

    // Kata kunci mencurigakan yang lebih spesifik
    const std::vector<std::wstring> SUSPICIOUS_KEYWORDS = {
        L"cheat",
        L"hack",
        L"debug",
        L"inject",
        L"olly",
        L"x64dbg",
        L"reclass",
        L"scylla",
        L"ida",
        L"processhacker",
        L"protection_id",
        L"wpesniff",
        L"rpesniff",
        L"memory",
        L"trainer",
        L"external",
        L"internal",
        L"bypass",
        L"nointro"
    };

    bool IsSystemModule(const std::wstring& modulePath) {
        if (modulePath.empty()) return false;

        std::wstring path = modulePath;
        std::transform(path.begin(), path.end(), path.begin(), ::towlower);

        // Cek path sistem Windows
        return (path.find(L"\\windows\\system32\\") != std::wstring::npos ||
            path.find(L"\\windows\\syswow64\\") != std::wstring::npos ||
            path.find(L"\\windows\\winsxs\\") != std::wstring::npos ||
            path.find(L"\\windows\\microsoft.net\\") != std::wstring::npos);
    }

    bool IsKnownGameModule(const std::wstring& moduleName) {
        std::wstring name = moduleName;
        std::transform(name.begin(), name.end(), name.begin(), ::towlower);

        for (const auto& allowed : GAME_MODULES) {
            // Handle wildcard untuk beberapa modul
            if (allowed.find(L"*") != std::wstring::npos) {
                // Cek jika nama modul cocok dengan pola wildcard sederhana
                size_t pos = allowed.find(L"*");
                std::wstring prefix = allowed.substr(0, pos);

                if (name.find(prefix) != std::wstring::npos) {
                    return true;
                }
            }
            else {
                if (name == allowed) {
                    return true;
                }
            }
        }

        return false;
    }

    bool IsSecuritySoftwareModule(const std::wstring& moduleName, const std::wstring& modulePath) {
        std::wstring name = moduleName;
        std::transform(name.begin(), name.end(), name.begin(), ::towlower);

        // Cek nama modul
        for (const auto& securityModule : SECURITY_MODULES) {
            if (name == securityModule) {
                return true;
            }
        }

        // Cek path modul untuk software keamanan
        std::wstring path = modulePath;
        std::transform(path.begin(), path.end(), path.begin(), ::towlower);

        return (path.find(L"\\avg\\") != std::wstring::npos ||
            path.find(L"\\malwarebytes\\") != std::wstring::npos ||
            path.find(L"\\mcafee\\") != std::wstring::npos ||
            path.find(L"\\eset\\") != std::wstring::npos ||
            path.find(L"\\kaspersky\\") != std::wstring::npos ||
            path.find(L"\\bitdefender\\") != std::wstring::npos ||
            path.find(L"\\windows\\system32\\wd\\") != std::wstring::npos); // Windows Defender
    }

    bool IsLegitimateOverlayModule(const std::wstring& moduleName) {
        std::wstring name = moduleName;
        std::transform(name.begin(), name.end(), name.begin(), ::towlower);

        for (const auto& overlay : LEGITIMATE_OVERLAYS) {
            if (name == overlay) {
                return true;
            }
        }

        return false;
    }

    bool IsModuleWhitelisted(const std::wstring& moduleName, const std::wstring& modulePath) {
        std::wstring name = moduleName;
        std::transform(name.begin(), name.end(), name.begin(), ::towlower);

        // Cek modul sistem
        for (const auto& systemModule : SYSTEM_MODULES) {
            if (systemModule.find(L"*") != std::wstring::npos) {
                size_t pos = systemModule.find(L"*");
                std::wstring prefix = systemModule.substr(0, pos);

                if (name.find(prefix) != std::wstring::npos) {
                    return true;
                }
            }
            else {
                if (name == systemModule) {
                    return true;
                }
            }
        }

        // Cek modul game
        if (IsKnownGameModule(name)) {
            return true;
        }

        // Cek modul keamanan
        if (IsSecuritySoftwareModule(name, modulePath)) {
            return true;
        }

        // Cek overlay yang sah
        if (IsLegitimateOverlayModule(name)) {
            return true;
        }

        // Cek path sistem
        if (IsSystemModule(modulePath)) {
            return true;
        }

        // Cek jika modul berada di folder game
        wchar_t gamePath[MAX_PATH];
        if (GetModuleFileNameW(NULL, gamePath, MAX_PATH)) {
            std::wstring gameDir = gamePath;
            size_t pos = gameDir.find_last_of(L"\\/");
            if (pos != std::wstring::npos) {
                gameDir = gameDir.substr(0, pos);

                std::wstring moduleDir = modulePath;
                pos = moduleDir.find_last_of(L"\\/");
                if (pos != std::wstring::npos) {
                    moduleDir = moduleDir.substr(0, pos);

                    if (_wcsnicmp(gameDir.c_str(), moduleDir.c_str(), gameDir.length()) == 0) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    bool DetectInjectedModules() {
        // Ambil handle snapshot dari semua modul dalam proses
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            return false;
        }

        MODULEENTRY32W me32;
        me32.dwSize = sizeof(MODULEENTRY32W);

        bool injectionDetected = false;
        std::wstring detectedModule;
        std::wstring detectionReason;

        // Enumerasi semua modul
        if (Module32FirstW(hSnapshot, &me32)) {
            do {
                std::wstring moduleName(me32.szModule);
                std::wstring modulePath(me32.szExePath);
                std::wstring normalizedModule = moduleName;
                std::transform(normalizedModule.begin(), normalizedModule.end(), normalizedModule.begin(), ::towlower);

                // Lewati jika di-whitelist
                if (IsModuleWhitelisted(normalizedModule, modulePath)) {
                    continue;
                }

                // Periksa jika modul memiliki karakteristik mencurigakan
                bool suspicious = false;
                std::wstring reason;

                // 1. Modul tanpa path (sering terjadi pada injected DLL)
                if (modulePath.empty()) {
                    suspicious = true;
                    reason = L"Module has no path (common for injected DLLs)";
                }
                else {
                    // 2. Periksa jika nama modul mengandung kata kunci mencurigakan
                    for (const auto& keyword : SUSPICIOUS_KEYWORDS) {
                        if (normalizedModule.find(keyword) != std::wstring::npos) {
                            suspicious = true;
                            reason = L"Module name contains suspicious keyword: " + keyword;
                            break;
                        }
                    }

                    // 3. Jika masih tidak mencurigakan, periksa memory protection
                    if (!suspicious) {
                        MEMORY_BASIC_INFORMATION mbi;
                        if (VirtualQuery(me32.modBaseAddr, &mbi, sizeof(mbi)) != 0) {
                            // Jika memory protection adalah PAGE_EXECUTE_READWRITE dan bukan MEM_IMAGE
                            if (mbi.Protect == PAGE_EXECUTE_READWRITE &&
                                (mbi.State == MEM_COMMIT) &&
                                mbi.Type != MEM_IMAGE) {

                                // Cek ukuran modul - injected DLL biasanya kecil
                                if (me32.modBaseSize < 1024 * 1024) { // 1MB
                                    suspicious = true;
                                    reason = L"Module has suspicious memory protection (PAGE_EXECUTE_READWRITE) and small size";
                                }
                            }
                        }
                    }
                }

                // 4. Jika masih tidak mencurigakan, cek jika modul tidak memiliki ekstensi DLL/EXE
                if (!suspicious && !modulePath.empty()) {
                    std::wstring ext = PathFindExtensionW(modulePath.c_str());
                    if (_wcsicmp(ext.c_str(), L".dll") != 0 &&
                        _wcsicmp(ext.c_str(), L".exe") != 0 &&
                        _wcsicmp(ext.c_str(), L".sys") != 0) {

                        suspicious = true;
                        reason = L"Module has non-standard extension: " + ext;
                    }
                }

                // 5. Jika masih tidak mencurigakan, cek jika modul tidak memiliki nama file yang valid
                if (!suspicious && !modulePath.empty()) {
                    std::wstring fileName = PathFindFileNameW(modulePath.c_str());
                    if (fileName.empty()) {
                        suspicious = true;
                        reason = L"Module has invalid file name";
                    }
                }

                // Jika mencurigakan, catat dan keluar dari loop
                if (suspicious) {
                    injectionDetected = true;
                    detectedModule = moduleName;
                    detectionReason = reason;
                    break;
                }
            } while (Module32NextW(hSnapshot, &me32));
        }

        CloseHandle(hSnapshot);

        return injectionDetected;
    }
}