#include "../pch.h"
#include "../include/AntiDebug.h"
#include "../include/Utils.h"
#include "../include/Logger.h"
#include "../include/EventReporter.h"
#include <windows.h>

// NT API typedefs
using NTSTATUS = LONG;
using pNtQueryInformationProcess = NTSTATUS (NTAPI *)(HANDLE, ULONG, PVOID, ULONG, PULONG);

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
namespace {
    bool IsDebuggerViaPeb() { return IsDebuggerPresent() != 0; }

    pNtQueryInformationProcess ResolveNtQueryInformationProcess() {
        static pNtQueryInformationProcess fn = []() -> pNtQueryInformationProcess {
            if (HMODULE ntdll = GetModuleHandleW(L"ntdll.dll"))
                return reinterpret_cast<pNtQueryInformationProcess>(GetProcAddress(ntdll, "NtQueryInformationProcess"));
            return nullptr;
        }();
        return fn;
    }

    bool CheckNtQueryInformationProcess() {
        auto NtQueryInformationProcess = ResolveNtQueryInformationProcess();
        if (!NtQueryInformationProcess)
            return false; // conservative: no API => treat as not detected

        HANDLE hProc = GetCurrentProcess();
        ULONG_PTR debugPort = 0; ULONG ret = 0;
        NTSTATUS st = NtQueryInformationProcess(hProc, ProcessDebugPort, &debugPort, sizeof(debugPort), &ret);
        if (st == STATUS_SUCCESS && debugPort != 0)
            return true;

        ULONG debugFlags = 0xFFFFFFFF; ret = 0;
        st = NtQueryInformationProcess(hProc, ProcessDebugFlags, &debugFlags, sizeof(debugFlags), &ret);
        if (st == STATUS_SUCCESS && debugFlags == 0)
            return true;

        HANDLE hDebugObj = nullptr; ret = 0;
        st = NtQueryInformationProcess(hProc, ProcessDebugObjectHandle, &hDebugObj, sizeof(hDebugObj), &ret);
        if (st == STATUS_SUCCESS && hDebugObj != nullptr)
            return true;
        return false;
    }
}

AntiDebug &AntiDebug::Instance() { static AntiDebug s; return s; }

bool AntiDebug::DetectDebugger() { return IsDebuggerViaPeb() || CheckNtQueryInformationProcess(); }

void AntiDebug::Tick() {
    if (DetectDebugger()) {
        EventReporter::SendDetection(L"AntiDebug", L"Debugger detected");
        ShowDetectionAndExit(L"Debugger terdeteksi");
    }
}
}
