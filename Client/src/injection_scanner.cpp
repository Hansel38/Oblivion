#include "../include/injection_scanner.h"
#include <Windows.h>
#include <TlHelp32.h>
#include <vector>
#include <string>

namespace InjectionScanner {
    // Daftar modul yang diizinkan (whitelist)
    const std::vector<std::wstring> WHITELISTED_MODULES = {
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
        L"rro.exe",  // Nama executable game
        L"oblivioneye.dll"  // Anti-cheat kita sendiri
    };

    bool IsModuleWhitelisted(const std::wstring& moduleName) {
        for (const auto& whitelisted : WHITELISTED_MODULES) {
            if (_wcsicmp(moduleName.c_str(), whitelisted.c_str()) == 0) {
                return true;
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

        // Enumerasi semua modul
        if (Module32FirstW(hSnapshot, &me32)) {
            do {
                std::wstring moduleName(me32.szModule);

                // Periksa jika modul tidak di-whitelist
                if (!IsModuleWhitelisted(moduleName)) {
                    // Periksa jika modul memiliki karakteristik mencurigakan
                    // Misalnya: tidak memiliki path di sistem (sering terjadi pada injected DLL)
                    if (wcsstr(me32.szExePath, L"\\Windows\\") == nullptr &&
                        wcsstr(me32.szExePath, L"\\System32\\") == nullptr &&
                        wcsstr(me32.szExePath, L"\\SysWOW64\\") == nullptr) {

                        // Periksa jika modul memiliki memory protection yang mencurigakan
                        MEMORY_BASIC_INFORMATION mbi;
                        if (VirtualQuery(me32.modBaseAddr, &mbi, sizeof(mbi)) != 0) {
                            // Jika memory protection adalah PAGE_EXECUTE_READWRITE tanpa alasan yang jelas
                            if (mbi.Protect == PAGE_EXECUTE_READWRITE &&
                                (mbi.State == MEM_COMMIT) &&
                                (mbi.Type == MEM_PRIVATE || mbi.Type == MEM_IMAGE)) {

                                // Deteksi lebih lanjut untuk meminimalkan false positive
                                // Beberapa game engine menggunakan memory dengan proteksi ini, jadi kita perlu verifikasi tambahan

                                // Jika nama modul mengandung kata kunci mencurigakan
                                if (wcsstr(moduleName.c_str(), L"cheat") != nullptr ||
                                    wcsstr(moduleName.c_str(), L"hack") != nullptr ||
                                    wcsstr(moduleName.c_str(), L"debug") != nullptr ||
                                    wcsstr(moduleName.c_str(), L"inject") != nullptr ||
                                    wcsstr(moduleName.c_str(), L"olly") != nullptr ||
                                    wcsstr(moduleName.c_str(), L"x64dbg") != nullptr) {
                                    CloseHandle(hSnapshot);
                                    return true;
                                }
                            }
                        }
                    }
                }
            } while (Module32NextW(hSnapshot, &me32));
        }

        CloseHandle(hSnapshot);
        return false;
    }
}