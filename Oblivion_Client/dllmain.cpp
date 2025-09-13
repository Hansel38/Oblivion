// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "include/ProcessWatcher.h"
#include "include/Heartbeat.h"
#include "include/OverlayScanner.h"
#include "include/DriverScanner.h"
#include "include/AntiDebug.h"
#include "include/AntiSuspend.h"
#include "include/ThreadRegistry.h"
#include "include/AntiInjection.h"
#include "include/DigitalSignatureScanner.h"
#include "include/AntiTestMode.h"
#include "include/SignatureScanner.h"
#include "include/PipeClient.h"
#include "include/HijackedThreadDetector.h"
#include "include/IATHookChecker.h"
#include "include/TestModeSpoofChecker.h"
#include "include/HWID.h"
#include "include/FileIntegrity.h"
#include "include/TcpClient.h"
#include "include/HandleProtection.h"
#include "include/PublisherWhitelist.h"
#include "include/PipeCommandClient.h"
#include "include/PrologHookChecker.h"
#include "include/NtdllIntegrity.h"
#include "include/Kernel32Integrity.h"
#include "include/User32Integrity.h"
#include "include/Gdi32Integrity.h"
#include "include/RuntimeStats.h"
#include "include/DetectorScheduler.h"
#include "include/PolicyManager.h"
#include "include/Logger.h"
#include <mutex>

extern "C" __declspec(dllexport) void OblivionEye_Entry() {}

namespace OblivionEye { static void RegisterTickDetectorsOnce(); }

namespace OblivionEye {
    static std::once_flag g_registerOnce;
    static void RegisterTickDetectorsOnce() {
        std::call_once(g_registerOnce, [](){
            auto& sched = DetectorScheduler::Instance();
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
            sched.Start();
            Log(L"Detector registration completed (once)");
        });
    }
}

static void LoadPolicySafe() {
    // Simplify: avoid mixed SEH/C++ to satisfy compiler (/EHsc)
    bool ok = false;
    try {
        ok = OblivionEye::PolicyManager::LoadPolicy(L"policy.txt");
    } catch (...) {
        ok = false;
    }
    if (!ok) {
        OblivionEye::Log(L"Policy: load failed or exception; embedded fallback in use");
    } else {
        OblivionEye::Log(L"Policy: loaded successfully");
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    switch (reason) {
    case DLL_PROCESS_ATTACH: {
        DisableThreadLibraryCalls(hModule);
        OblivionEye::HandleProtection::Apply();
        OblivionEye::RuntimeStats::Instance().SetStartTick();
        OblivionEye::RegisterThreadId(GetCurrentThreadId());
        OblivionEye::PipeClient::Instance().Start(L"\\\\.\\pipe\\OblivionEye");
        OblivionEye::PipeCommandClient::Instance().Start(L"\\\\.\\pipe\\OblivionEyeCmd");
        LoadPolicySafe();
        OblivionEye::ProcessWatcher::Instance().Start();
        OblivionEye::RegisterTickDetectorsOnce();
        break; }
    case DLL_THREAD_ATTACH:
        OblivionEye::RegisterThreadId(GetCurrentThreadId());
        break;
    case DLL_THREAD_DETACH:
        OblivionEye::UnregisterThreadId(GetCurrentThreadId());
        break;
    case DLL_PROCESS_DETACH:
        OblivionEye::DetectorScheduler::Instance().Stop();
        OblivionEye::PipeCommandClient::Instance().Stop();
        OblivionEye::TcpClient::Instance().Stop();
        OblivionEye::PipeClient::Instance().Stop();
        break;
    }
    return TRUE;
}

