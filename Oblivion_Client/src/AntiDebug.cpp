#include "../pch.h"
#include "../include/AntiDebug.h"
#include "../include/Utils.h"
#include "../include/Logger.h"
#include "../include/EventReporter.h"
#include <windows.h>
#include <thread>
#include <chrono>

// NT API
typedef LONG NTSTATUS;
typedef NTSTATUS (NTAPI *pNtQueryInformationProcess)(HANDLE, ULONG, PVOID, ULONG, PULONG);

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

#ifndef ProcessDebugPort
#define ProcessDebugPort 7
#endif
#ifndef ProcessDebugFlags
#define ProcessDebugFlags 31
#endif
#ifndef ProcessDebugObjectHandle
#define ProcessDebugObjectHandle 30
#endif

namespace OblivionEye {

    AntiDebug& AntiDebug::Instance() { static AntiDebug s; return s; }

    static bool IsDebuggerPEB() {
        return IsDebuggerPresent() ? true : false;
    }

    static bool CheckNtQueryInformationProcess() {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (!ntdll) return false;
        auto NtQueryInformationProcess = reinterpret_cast<pNtQueryInformationProcess>(GetProcAddress(ntdll, "NtQueryInformationProcess"));
        if (!NtQueryInformationProcess) return false;

        HANDLE hProc = GetCurrentProcess();
        ULONG_PTR debugPort = 0; ULONG ret = 0;
        NTSTATUS st = NtQueryInformationProcess(hProc, ProcessDebugPort, &debugPort, sizeof(debugPort), &ret);
        if (st == STATUS_SUCCESS && debugPort != 0) return true;

        // DebugFlags: 0 = debugged, 1 = not debugged
        ULONG debugFlags = 0xFFFFFFFF; ret = 0;
        st = NtQueryInformationProcess(hProc, ProcessDebugFlags, &debugFlags, sizeof(debugFlags), &ret);
        if (st == STATUS_SUCCESS && debugFlags == 0) return true;

        HANDLE hDebugObj = nullptr; ret = 0;
        st = NtQueryInformationProcess(hProc, ProcessDebugObjectHandle, &hDebugObj, sizeof(hDebugObj), &ret);
        if (st == STATUS_SUCCESS && hDebugObj != nullptr) return true;

        return false;
    }

    bool AntiDebug::DetectDebugger() {
        if (IsDebuggerPEB()) return true;
        if (CheckNtQueryInformationProcess()) return true;
        return false;
    }

    void AntiDebug::Start(unsigned intervalMs) {
        if (m_running.exchange(true)) return;
        std::thread([this, intervalMs]() { Loop(intervalMs); }).detach();
    }

    void AntiDebug::Stop() { m_running = false; }

    void AntiDebug::Loop(unsigned intervalMs) {
        Log(L"AntiDebug start");
        while (m_running) {
            if (DetectDebugger()) {
                EventReporter::SendDetection(L"AntiDebug", L"Debugger detected");
                ShowDetectionAndExit(L"Debugger terdeteksi");
                return;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(intervalMs));
        }
        Log(L"AntiDebug stop");
    }
}
