#include "../include/ThreadWatcher.h"
#include "../include/Blacklist.h"
#include <tlhelp32.h>
#include <algorithm>
#include <cctype>
#include <vector>
#include <iostream> // Untuk debugging, bisa dihapus nanti

namespace OblivionEye {

    bool ThreadWatcher::IsModuleInBlacklist(const std::wstring& moduleName) {
        const auto& blacklist = GetBlacklistedProcesses();
        for (const auto& blacklistedProcess : blacklist) {
            if (_wcsicmp(moduleName.c_str(), blacklistedProcess.c_str()) == 0) {
                return true;
            }
        }
        return false;
    }

    bool ThreadWatcher::ScanForSuspiciousThreads() {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            return false; // Gagal membuat snapshot
        }

        THREADENTRY32 te32;
        te32.dwSize = sizeof(THREADENTRY32);

        if (!Thread32First(hSnapshot, &te32)) {
            CloseHandle(hSnapshot);
            return false; // Gagal mendapatkan thread pertama
        }

        bool detected = false;
        do {
            // Dapatkan handle thread
            HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT, FALSE, te32.th32ThreadID);
            if (hThread != NULL) {
                CONTEXT ctx;
                ctx.ContextFlags = CONTEXT_FULL;
                if (GetThreadContext(hThread, &ctx)) {
                    // Cek konteks thread untuk alamat yang mencurigakan
                    // Contoh: jika EIP (Extended Instruction Pointer) mengarah ke alamat yang tidak valid
                    // Anda bisa tambahkan logika lebih lanjut di sini

                    // Dapatkan module yang terkait dengan thread
                    HMODULE hModules[1024];
                    DWORD cbNeeded;
                    if (EnumProcessModules(GetCurrentProcess(), hModules, sizeof(hModules), &cbNeeded)) {
                        for (DWORD i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
                            TCHAR szModName[MAX_PATH];
                            if (GetModuleFileNameEx(GetCurrentProcess(), hModules[i], szModName, sizeof(szModName) / sizeof(TCHAR))) {
                                std::wstring moduleName = szModName;
                                if (IsModuleInBlacklist(moduleName)) {
                                    detected = true;
                                    // std::wcout << L"Thread terdeteksi dari module: " << moduleName << std::endl; // Debug
                                    break;
                                }
                            }
                        }
                    }
                }
                CloseHandle(hThread);
            }
        } while (Thread32Next(hSnapshot, &te32));

        CloseHandle(hSnapshot);
        return detected;
    }

} // namespace OblivionEye