#include "../include/AntiDebug.h"
#include "../include/Logger.h"
#include <windows.h>
#include <intrin.h>
#include <winternl.h>

// Fungsi terpisah untuk SEH (tanpa objek C++)
extern "C" bool Int3Check() {
    __try {
        __asm {
            int 3
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    return true;
}

extern "C" bool SEHCheck() {
    __try {
        RaiseException(EXCEPTION_BREAKPOINT, 0, 0, NULL);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    return true;
}

// Import NtQueryInformationProcess
typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    ULONG ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
    );

// 1. IsDebuggerPresent (dasar)
bool AntiDebug::CheckIsDebuggerPresent() {
    if (IsDebuggerPresent()) {
        Logger::LogDetected("IsDebuggerPresent detected debugger");
        return true;
    }
    return false;
}

// 2. CheckRemoteDebuggerPresent
bool AntiDebug::CheckRemoteDebugger() {
    BOOL isRemoteDebugger = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &isRemoteDebugger)) {
        if (isRemoteDebugger) {
            Logger::LogDetected("Remote debugger detected");
            return true;
        }
    }
    return false;
}

// 3. Hardware Breakpoint Detection
bool AntiDebug::CheckHardwareBreakpoints() {
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (GetThreadContext(GetCurrentThread(), &ctx)) {
        if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0) {
            Logger::LogDetected("Hardware breakpoint detected");
            return true;
        }
    }
    return false;
}

// 4. Timing Check (Perbaiki dengan GetTickCount64)
bool AntiDebug::CheckTiming() {
    ULONGLONG start = GetTickCount64();
    Sleep(50); // Tambah waktu sleep agar lebih stabil
    ULONGLONG end = GetTickCount64();
    ULONGLONG elapsed = end - start;

    // Naikkan threshold jadi 200ms dan gunakan ULONGLONG
    if (elapsed > 200) {
        Logger::LogDetected("Timing anomaly detected (possible debugging)");
        return true;
    }
    return false;
}

// 5. NtQueryInformationProcess (Perbaiki)
bool AntiDebug::CheckNtQueryInfo() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return false;

    pNtQueryInformationProcess NtQueryInfo = (pNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
    if (!NtQueryInfo) return false;

    // Gunakan ProcessDebugPort (0x7) yang lebih reliable
    DWORD debugPort = 0;
    NTSTATUS status = NtQueryInfo(GetCurrentProcess(), 0x7, &debugPort, sizeof(DWORD), NULL);

    if (NT_SUCCESS(status) && debugPort != 0) {
        Logger::LogDetected("NtQueryInformationProcess detected debugger (DebugPort)");
        return true;
    }
    return false;
}

// 6. OutputDebugString Trick
bool AntiDebug::CheckOutputDebugString() {
    SetLastError(0);
    OutputDebugStringA("AntiDebug Check");
    if (GetLastError() != 0) {
        Logger::LogDetected("OutputDebugString detected debugger");
        return true;
    }
    return false;
}

// 7. Int 3 Detection (panggil fungsi terpisah)
bool AntiDebug::CheckInt3() {
    if (Int3Check()) {
        Logger::LogDetected("Int3 breakpoint detected");
        return true;
    }
    return false;
}

// 8. SEH Manipulation Detection (panggil fungsi terpisah)
bool AntiDebug::CheckSEH() {
    if (SEHCheck()) {
        Logger::LogDetected("SEH manipulation detected");
        return true;
    }
    return false;
}

// Fungsi utama
bool AntiDebug::IsDebuggerDetected() {
    if (CheckIsDebuggerPresent()) return true;
    if (CheckRemoteDebugger()) return true;
    if (CheckHardwareBreakpoints()) return true;
    if (CheckTiming()) return true;
    if (CheckNtQueryInfo()) return true;
    if (CheckOutputDebugString()) return true;
    if (CheckInt3()) return true;
    if (CheckSEH()) return true;
    return false;
}