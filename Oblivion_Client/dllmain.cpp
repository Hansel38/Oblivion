// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"

// Project headers (alphabetically grouped)
#include "include/AntiDebug.h"
#include "include/AntiInjection.h"
#include "include/AntiSuspend.h"
#include "include/AntiTestMode.h"
#include "include/DetectorScheduler.h"
#include "include/DigitalSignatureScanner.h"
#include "include/EATHookChecker.h"
#include "include/FileIntegrity.h"
#include "include/Gdi32Integrity.h"
#include "include/HWID.h"
#include "include/HandleProtection.h"
#include "include/Heartbeat.h"
#include "include/HijackedThreadDetector.h"
#include "include/IATHookChecker.h"
#include "include/Kernel32Integrity.h"
#include "include/Logger.h"
#include "include/NtdllIntegrity.h"
#include "include/OverlayScanner.h"
#include "include/PipeClient.h"
#include "include/PipeCommandClient.h"
#include "include/PolicyManager.h"
#include "include/ProcessWatcher.h"
#include "include/PrologHookChecker.h"
#include "include/PublisherWhitelist.h"
#include "include/RuntimeStats.h"
#include "include/SignatureScanner.h"
#include "include/SyscallStubChecker.h"
#include "include/TcpClient.h"
#include "include/TestModeSpoofChecker.h"
#include "include/ThreadRegistry.h"
#include "include/User32Integrity.h"
#include "include/SelfCheck.h"
#include "include/ModuleSectionIntegrity.h"
#include "include/KernelSurfaceStub.h"
#include "include/MemoryHeuristics.h"

#include <mutex>

extern "C" __declspec(dllexport) void OblivionEye_Entry() {}

namespace OblivionEye {
    // Ensures detectors are registered exactly once irrespective of how many times initialization is attempted.
    static std::once_flag g_registerOnce;

    static void RegisterTickDetectorsOnce() {
        std::call_once(g_registerOnce, []() {
            auto &sched = DetectorScheduler::Instance();
            sched.Add(&ProcessWatcher::Instance());
            sched.Add(&AntiTestMode::Instance());
            sched.Add(&AntiInjection::Instance());
            sched.Add(&DigitalSignatureScanner::Instance());
            sched.Add(&OverlayScanner::Instance());
            sched.Add(&AntiDebug::Instance());
            sched.Add(&AntiSuspend::Instance());
            sched.Add(&Heartbeat::Instance());
            sched.Add(&SignatureScanner::Instance());
            sched.Add(&HijackedThreadDetector::Instance());
            sched.Add(&IATHookChecker::Instance());
            sched.Add(&PrologHookChecker::Instance());
            sched.Add(&NtdllIntegrity::Instance());
            sched.Add(&Kernel32Integrity::Instance());
            sched.Add(&User32Integrity::Instance());
            sched.Add(&Gdi32Integrity::Instance());
            sched.Add(&TestModeSpoofChecker::Instance());
            sched.Add(&EATHookChecker::Instance());
            sched.Add(&SyscallStubChecker::Instance());
            sched.Add(&KernelSurfaceStub::Instance());
            sched.Add(&MemoryHeuristics::Instance());
            // New phase: aggregate section integrity across core modules (ntdll, kernel32, user32)
            struct ModuleSectionIntegrityAdapter : IDetector {
                const wchar_t* Name() const override { return L"ModuleSectionIntegrity"; }
                unsigned IntervalMs() const override { return OblivionEye::Config::MEM_SEC_INTEGRITY_INTERVAL_MS; }
                void Tick() override { ModuleSectionIntegrity::Instance().Tick(); }
            };
            static ModuleSectionIntegrityAdapter g_modSecInt;
            sched.Add(&g_modSecInt);
            sched.Start();
            Log(L"Detector registration completed (once)");
        });
    }

    static void LoadPolicySafe() {
        bool ok = false;
        try {
            ok = PolicyManager::LoadPolicy(L"policy.txt");
        } catch (...) {
            ok = false; // swallow; we only log below
        }
        if (!ok) {
            Log(L"Policy: load failed or exception; embedded fallback in use");
        } else {
            Log(L"Policy: loaded successfully");
        }
    }

    // Process-level initialization
    static void OnProcessAttach(HMODULE hModule) {
        DisableThreadLibraryCalls(hModule);
        HandleProtection::Apply();
        RuntimeStats::Instance().SetStartTick();
        RegisterThreadId(GetCurrentThreadId());
        PipeClient::Instance().Start(L"\\\\.\\pipe\\OblivionEye");
        PipeCommandClient::Instance().Start(L"\\\\.\\pipe\\OblivionEyeCmd");
        LoadPolicySafe();
        ProcessWatcher::Instance().Start();
        RegisterTickDetectorsOnce();
        // Optional internal self-check triggered via environment variable OBLIVION_SELFTEST=1
        wchar_t val[8]; DWORD got = GetEnvironmentVariableW(L"OBLIVION_SELFTEST", val, 8);
        if(got>0 && got < 8 && val[0]==L'1') {
            auto report = RunInternalSelfCheck();
            // Log first line only (full report could be large); optionally could send through pipe
            LogSec(L"SelfCheck invoked");
        }
    }

    // Process-level shutdown
    static void OnProcessDetach() {
        DetectorScheduler::Instance().Stop();
        PipeCommandClient::Instance().Stop();
        TcpClient::Instance().Stop();
        PipeClient::Instance().Stop();
    }

    static void OnThreadAttach() { RegisterThreadId(GetCurrentThreadId()); }
    static void OnThreadDetach() { UnregisterThreadId(GetCurrentThreadId()); }
} // namespace OblivionEye

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID /*lpReserved*/) {
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        OblivionEye::OnProcessAttach(hModule);
        break;
    case DLL_THREAD_ATTACH:
        OblivionEye::OnThreadAttach();
        break;
    case DLL_THREAD_DETACH:
        OblivionEye::OnThreadDetach();
        break;
    case DLL_PROCESS_DETACH:
        OblivionEye::OnProcessDetach();
        break;
    }
    return TRUE;
}

