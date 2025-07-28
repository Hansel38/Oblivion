#include "../include/anti_debug.h"
#include <Windows.h>
#include <winternl.h>
#include <vector>
#include <string>
#include "../include/utils.h"

// Definisi manual untuk STATUS_INFO_LENGTH_MISMATCH
#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004
#endif

// Definisi untuk NtQuerySystemInformation
typedef LONG(NTAPI* NtQuerySystemInformation_t)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

// Definisi untuk NtQueryInformationProcess
typedef LONG(NTAPI* NtQueryInformationProcess_t)(
    HANDLE ProcessHandle,
    ULONG ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
    );

namespace AntiDebug {
    bool CheckDebuggerPresent() {
        // Metode 1: IsDebuggerPresent API
        if (IsDebuggerPresent()) {
            return true;
        }

        // Metode 2: CheckRemoteDebuggerPresent
        BOOL isDebuggerPresent = FALSE;
        if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebuggerPresent) && isDebuggerPresent) {
            return true;
        }

        return false;
    }

    bool CheckNtQuerySystemInformation() {
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (!hNtdll) return false;

        NtQuerySystemInformation_t NtQuerySystemInformation =
            (NtQuerySystemInformation_t)GetProcAddress(hNtdll, "NtQuerySystemInformation");
        if (!NtQuerySystemInformation) return false;

        // Query informasi proses
        ULONG bufferSize = 0x1000;
        std::vector<BYTE> buffer(bufferSize);

        // Gunakan STATUS_INFO_LENGTH_MISMATCH dengan definisi manual
        NTSTATUS status = NtQuerySystemInformation(SystemProcessInformation, buffer.data(), bufferSize, &bufferSize);
        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            buffer.resize(bufferSize);
            status = NtQuerySystemInformation(SystemProcessInformation, buffer.data(), bufferSize, &bufferSize);
        }

        if (NT_SUCCESS(status)) {
            PSYSTEM_PROCESS_INFORMATION processInfo = (PSYSTEM_PROCESS_INFORMATION)buffer.data();
            DWORD currentPid = GetCurrentProcessId();

            while (true) {
                if ((DWORD)(DWORD_PTR)processInfo->UniqueProcessId == currentPid) {
                    // Gunakan NtQueryInformationProcess untuk memeriksa DebugPort
                    NtQueryInformationProcess_t NtQueryInformationProcess =
                        (NtQueryInformationProcess_t)GetProcAddress(hNtdll, "NtQueryInformationProcess");

                    if (NtQueryInformationProcess) {
                        // ProcessDebugPort (7)
                        HANDLE hDebugPort = 0;
                        NTSTATUS statusDebugPort = NtQueryInformationProcess(GetCurrentProcess(), 7,
                            &hDebugPort, sizeof(hDebugPort), NULL);
                        if (NT_SUCCESS(statusDebugPort) && hDebugPort != 0) {
                            return true;
                        }

                        // ProcessDebugFlags (24)
                        ULONG uDebugFlags = 0;
                        NTSTATUS statusDebugFlags = NtQueryInformationProcess(GetCurrentProcess(), 24,
                            &uDebugFlags, sizeof(uDebugFlags), NULL);
                        if (NT_SUCCESS(statusDebugFlags) && uDebugFlags != 0) {
                            return true;
                        }
                    }

                    break;
                }

                if (processInfo->NextEntryOffset == 0) break;
                processInfo = (PSYSTEM_PROCESS_INFORMATION)((BYTE*)processInfo + processInfo->NextEntryOffset);
            }
        }

        return false;
    }

    bool CheckDebugRegisters() {
        CONTEXT ctx = { 0 };
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

        if (GetThreadContext(GetCurrentThread(), &ctx)) {
            // Periksa hanya bit yang relevan untuk breakpoint
            if ((ctx.Dr7 & 0x00000055) != 0) {
                // Verifikasi apakah breakpoint benar-benar aktif
                if ((ctx.Dr7 & 0x00000003) != 0 ||
                    (ctx.Dr7 & 0x0000000C) != 0 ||
                    (ctx.Dr7 & 0x00000030) != 0 ||
                    (ctx.Dr7 & 0x000000C0) != 0) {
                    return true;
                }
            }
        }

        return false;
    }

    bool IsSecuritySoftwareDebugger() {
        // Daftar proses keamanan yang mungkin mengatur DebugPort
        const std::vector<std::wstring> securitySoftware = {
            L"MsMpEng.exe",      // Windows Defender
            L"MsSense.exe",      // Windows Defender Advanced Threat Protection
            L"AvastUI.exe",      // Avast
            L"avgui.exe",        // AVG
            L"mbam.exe",         // Malwarebytes
            L"ccSvcHst.exe",     // Norton
            L"spidernt.exe"      // McAfee
        };

        // Periksa jika proses keamanan sedang berjalan
        for (const auto& process : securitySoftware) {
            if (Utils::IsProcessRunning(process)) {
                return true;
            }
        }

        return false;
    }

    bool CheckRegistryForDebuggers() {
        // Hanya periksa key untuk debugger khusus
        const std::vector<std::wstring> debuggerKeys = {
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\OLLYDBG.EXE",
            L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\App Paths\\OLLYDBG.EXE",
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\X64DBG.EXE",
            L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\App Paths\\X64DBG.EXE",
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\RECLASS.NET.EXE",
            L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\App Paths\\RECLASS.NET.EXE"
        };

        for (const auto& key : debuggerKeys) {
            HKEY hKey;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, key.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                RegCloseKey(hKey);
                return true;
            }
        }

        return false;
    }

    bool IsDebugged() {
        // Level 1: Pemeriksaan cepat dan aman
        if (CheckDebuggerPresent()) {
            return true;
        }

        // Level 2: Pemeriksaan lebih mendalam dengan verifikasi tambahan
        bool isSecuritySoftwareRunning = IsSecuritySoftwareDebugger();

        if (!isSecuritySoftwareRunning && CheckNtQuerySystemInformation()) {
            // Verifikasi tambahan
            STARTUPINFOW si = { sizeof(STARTUPINFOW) };
            PROCESS_INFORMATION pi;

            if (!CreateProcessW(NULL, (LPWSTR)L"cmd.exe", NULL, NULL, FALSE,
                CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
                if (GetLastError() == ERROR_ACCESS_DENIED) {
                    return true; // Sangat mungkin di-debug
                }
            }
            else {
                ResumeThread(pi.hThread);
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
            }

            return true;
        }

        // Level 3: Pemeriksaan register debug
        if (CheckDebugRegisters()) {
            // Verifikasi dengan metode tambahan
            if (CheckDebuggerPresent()) {
                return true;
            }
        }

        // Level 4: Pemeriksaan registry untuk debugger khusus
        if (CheckRegistryForDebuggers()) {
            return true;
        }

        return false;
    }
}