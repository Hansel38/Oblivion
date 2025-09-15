#include "../pch.h"
#include "../include/HijackedThreadDetector.h"
#include "../include/Logger.h"
#include "../include/Utils.h"
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <vector>

#pragma comment(lib, "psapi.lib")

namespace OblivionEye {
namespace {
    using NTSTATUS = LONG;
    using pNtQueryInformationThread = NTSTATUS (NTAPI *)(HANDLE, ULONG, PVOID, ULONG, PULONG);

    pNtQueryInformationThread ResolveNtQueryInformationThread() {
        static pNtQueryInformationThread fn = []() -> pNtQueryInformationThread {
            if (HMODULE ntdll = GetModuleHandleW(L"ntdll.dll"))
                return reinterpret_cast<pNtQueryInformationThread>(GetProcAddress(ntdll, "NtQueryInformationThread"));
            return nullptr;
        }();
        return fn;
    }

    bool IsAddressInsideAnyModule(void *addr) {
        if (!addr) return true; // treat null as safe (cannot classify)
        HMODULE mods[1024] = {}; DWORD needed = 0;
        if (!EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &needed))
            return true; // fail safe
        int count = static_cast<int>(needed / sizeof(HMODULE));
        MODULEINFO mi{}; auto p = reinterpret_cast<uint8_t*>(addr);
        for (int i = 0; i < count; ++i) {
            if (GetModuleInformation(GetCurrentProcess(), mods[i], &mi, sizeof(mi))) {
                auto base = static_cast<uint8_t*>(mi.lpBaseOfDll);
                size_t size = static_cast<size_t>(mi.SizeOfImage);
                if (p >= base && p < base + size)
                    return true;
            }
        }
        return false;
    }

    bool GetThreadStartAddress(HANDLE hThread, void **outAddr) {
        *outAddr = nullptr;
        auto NtQueryInformationThread = ResolveNtQueryInformationThread();
        if (!NtQueryInformationThread)
            return false;
        ULONG_PTR start = 0; ULONG ret = 0;
        NTSTATUS st = NtQueryInformationThread(hThread, 9, &start, sizeof(start), &ret); // ThreadQuerySetWin32StartAddress
        if (st != 0)
            return false;
        *outAddr = reinterpret_cast<void*>(start);
        return true;
    }

    bool IsThreadInKnownModule(HANDLE hThread) {
        void *startAddr = nullptr;
        if (!GetThreadStartAddress(hThread, &startAddr))
            return true; // skip classification on failure
        return IsAddressInsideAnyModule(startAddr);
    }
}

HijackedThreadDetector &HijackedThreadDetector::Instance() { static HijackedThreadDetector s; return s; }

bool HijackedThreadDetector::ScanThreads() {
    DWORD pid = GetCurrentProcessId();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return false;

    THREADENTRY32 te{}; te.dwSize = sizeof(te);
    bool detection = false;
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid)
                continue;
            HANDLE hThread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION | THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
            if (!hThread)
                continue;
            bool ok = IsThreadInKnownModule(hThread);
            CloseHandle(hThread);
            if (!ok) {
                detection = true;
                break;
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);

    if (detection) {
        ShowDetectionAndExit(L"Hijacked thread terdeteksi (start address di luar module)");
        return true;
    }
    return false;
}

void HijackedThreadDetector::Tick() { ScanThreads(); }
}
