#include <windows.h>
#include <psapi.h> // Untuk GetModuleInformation
#include "include/ProcessWatcher.h"
#include "include/OverlayScanner.h"
#include "include/AntiDebug.h"
#include "include/InjectionScanner.h"
#include "include/MemoryScanner.h" // Modul terbaru
#include "include/Logger.h"
#include <thread>

// Fungsi alert langsung close
void TriggerAlertAndExit(const char* msg) {
    Logger::LogDetected(msg);
    Logger::Close();
    FatalAppExitA(0, msg);
}

void OblivionEye_Main() {
    // Scan sekali saat startup - Process
    if (ProcessWatcher::IsBlacklistedProcessRunning()) {
        TriggerAlertAndExit("Cheat process detected! Game will close.");
        return;
    }

    // Scan sekali saat startup - Overlay
    if (OverlayScanner::IsOverlayDetected()) {
        TriggerAlertAndExit("Overlay detected! Game will close.");
        return;
    }

    // Scan sekali saat startup - Anti-Debug
    if (AntiDebug::IsDebuggerDetected()) {
        TriggerAlertAndExit("Debugger detected! Game will close.");
        return;
    }

    // Scan sekali saat startup - Injection
    if (InjectionScanner::IsInjectedDllDetected()) {
        TriggerAlertAndExit("Injected DLL detected! Game will close.");
        return;
    }

    // Scan sekali saat startup - Memory Tampering
    if (MemoryScanner::IsMemoryTampered()) {
        TriggerAlertAndExit("Memory tampering detected! Game will close.");
        return;
    }

    while (true) {
        // Scan process
        if (ProcessWatcher::IsBlacklistedProcessRunning()) {
            TriggerAlertAndExit("Cheat process detected! Game will close.");
            return;
        }

        // Scan overlay
        if (OverlayScanner::IsOverlayDetected()) {
            TriggerAlertAndExit("Overlay detected! Game will close.");
            return;
        }

        // Scan debugger
        if (AntiDebug::IsDebuggerDetected()) {
            TriggerAlertAndExit("Debugger detected! Game will close.");
            return;
        }

        // Scan injected DLL
        if (InjectionScanner::IsInjectedDllDetected()) {
            TriggerAlertAndExit("Injected DLL detected! Game will close.");
            return;
        }

        // Scan memory tampering
        if (MemoryScanner::IsMemoryTampered()) {
            TriggerAlertAndExit("Memory tampering detected! Game will close.");
            return;
        }

        Sleep(2000);
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)OblivionEye_Main, NULL, 0, NULL);
        break;
    case DLL_PROCESS_DETACH:
        Logger::Close();
        break;
    }
    return TRUE;
}

// Exported function for Stud_PE
extern "C" __declspec(dllexport) void OblivionEye_Entry() {}