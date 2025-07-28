#include <Windows.h>
#include "../include/process_watcher.h"
#include "../include/overlay_scanner.h"
#include "../include/anti_debug.h"
#include "../include/anti_suspend.h"
#include "../include/injection_scanner.h"
#include "../include/memory_scanner.h"
#include "../include/utils.h"

// Fungsi export untuk Stud_PE seperti yang diminta
extern "C" __declspec(dllexport) void OblivionEye_Entry() {}

// Fungsi untuk scan berkala
void __stdcall ScanThread() {
    // Tambahkan delay awal yang lebih lama untuk memastikan game sudah benar-benar berjalan
    Sleep(15000);  // 15 detik

    // Inisialisasi monitoring thread
    AntiSuspend::InitializeThreadMonitoring();

    // Tambahkan region memori game ke whitelist
    MEMORY_BASIC_INFORMATION gameModuleInfo;
    HMODULE hGameModule = GetModuleHandleW(NULL);
    if (hGameModule && VirtualQuery(hGameModule, &gameModuleInfo, sizeof(gameModuleInfo))) {
        MemoryScanner::AddToWhitelist((BYTE*)gameModuleInfo.BaseAddress, gameModuleInfo.RegionSize);
    }

    // Tambahkan region memori OblivionEye ke whitelist
    HMODULE hOblivionEye = GetModuleHandleW(L"OblivionEye.dll");
    if (hOblivionEye && VirtualQuery(hOblivionEye, &gameModuleInfo, sizeof(gameModuleInfo))) {
        MemoryScanner::AddToWhitelist((BYTE*)gameModuleInfo.BaseAddress, gameModuleInfo.RegionSize);
    }

    while (true) {
        // Cek proses berbahaya
        if (ProcessWatcher::CheckBlacklistedProcesses()) {
            Utils::CloseGame();
            break;
        }

        // Cek overlay windows
        if (OverlayScanner::DetectOverlayWindows()) {
            Utils::CloseGame();
            break;
        }

        // Cek apakah sedang di-debug
        if (AntiDebug::IsDebugged()) {
            Utils::CloseGame();
            break;
        }

        // Cek apakah thread di-suspend
        if (AntiSuspend::IsThreadSuspended()) {
            Utils::CloseGame();
            break;
        }

        // Cek apakah ada modul yang di-inject
        if (InjectionScanner::DetectInjectedModules()) {
            Utils::CloseGame();
            break;
        }

        // Cek signature di memori
        if (MemoryScanner::ScanMemoryForSignatures()) {
            Utils::CloseGame();
            break;
        }

        Sleep(20000); // Scan setiap 20 detik
    }

    // Hentikan monitoring thread
    AntiSuspend::StopThreadMonitoring();
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
    {
        // HANYA buat thread untuk scan berkala di sini
        // JANGAN LAKUKAN OPERASI BERAT DI SINI
        DisableThreadLibraryCalls(hModule);

        // Gunakan CreateThread dengan benar
        HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ScanThread, NULL, 0, NULL);
        if (hThread) {
            CloseHandle(hThread);
        }
        break;
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}