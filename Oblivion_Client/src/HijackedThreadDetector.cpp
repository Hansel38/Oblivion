#include "../pch.h"
#include "../include/HijackedThreadDetector.h"
#include "../include/Logger.h"
#include "../include/Utils.h"
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <vector>
#include <thread>
#include <chrono>

#pragma comment(lib, "psapi.lib")

namespace OblivionEye {

    // NT API typdef (tanpa header winternl)
    typedef LONG NTSTATUS;
    typedef NTSTATUS (NTAPI *pNtQueryInformationThread)(HANDLE, ULONG, PVOID, ULONG, PULONG);

    HijackedThreadDetector& HijackedThreadDetector::Instance() { static HijackedThreadDetector s; return s; }

    static bool IsAddressInsideAnyModule(void* addr) {
        if (!addr) return true; // treat sebagai aman jika tidak valid
        HMODULE mods[1024] = {};
        DWORD needed = 0;
        if (!EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &needed)) return true; // gagal enum -> jangan flag
        int count = needed / sizeof(HMODULE);
        MODULEINFO mi{};
        auto p = reinterpret_cast<uint8_t*>(addr);
        for (int i = 0; i < count; ++i) {
            if (GetModuleInformation(GetCurrentProcess(), mods[i], &mi, sizeof(mi))) {
                auto base = reinterpret_cast<uint8_t*>(mi.lpBaseOfDll);
                size_t size = static_cast<size_t>(mi.SizeOfImage);
                if (p >= base && p < base + size) return true;
            }
        }
        return false;
    }

    static bool GetThreadStartAddress(HANDLE hThread, void** outAddr) {
        *outAddr = nullptr;
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (!ntdll) return false;
        auto NtQueryInformationThread = reinterpret_cast<pNtQueryInformationThread>(GetProcAddress(ntdll, "NtQueryInformationThread"));
        if (!NtQueryInformationThread) return false;
        ULONG_PTR start = 0; ULONG ret = 0;
        NTSTATUS st = NtQueryInformationThread(hThread, 9 /*ThreadQuerySetWin32StartAddress*/, &start, sizeof(start), &ret);
        if (st != 0) return false;
        *outAddr = reinterpret_cast<void*>(start);
        return true;
    }

    static bool IsThreadInKnownModule(HANDLE hThread) {
        void* startAddr = nullptr;
        if (!GetThreadStartAddress(hThread, &startAddr)) {
            // Jika tidak bisa didapat, jangan anggap buruk (hindari false positive)
            return true;
        }
        return IsAddressInsideAnyModule(startAddr);
    }

    bool HijackedThreadDetector::ScanThreads() {
        DWORD pid = GetCurrentProcessId();
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snap == INVALID_HANDLE_VALUE) return false;
        THREADENTRY32 te{}; te.dwSize = sizeof(te);
        if (Thread32First(snap, &te)) {
            do {
                if (te.th32OwnerProcessID != pid) continue;
                HANDLE hThread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION | THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                if (!hThread) continue;
                if (!IsThreadInKnownModule(hThread)) {
                    CloseHandle(hThread);
                    CloseHandle(snap);
                    ShowDetectionAndExit(L"Hijacked thread terdeteksi (start address di luar module)");
                    return true;
                }
                CloseHandle(hThread);
            } while (Thread32Next(snap, &te));
        }
        CloseHandle(snap);
        return false;
    }

    void HijackedThreadDetector::Start(unsigned intervalMs) {
        if (m_running.exchange(true)) return;
        std::thread([this, intervalMs]() { Loop(intervalMs); }).detach();
    }

    void HijackedThreadDetector::Stop() { m_running = false; }

    void HijackedThreadDetector::Loop(unsigned intervalMs) {
        Log(L"HijackedThreadDetector start");
        while (m_running) {
            if (ScanThreads()) return;
            std::this_thread::sleep_for(std::chrono::milliseconds(intervalMs));
        }
        Log(L"HijackedThreadDetector stop");
    }
}
