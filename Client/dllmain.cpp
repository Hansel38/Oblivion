#include <Windows.h>
#include "../include/process_watcher.h"
#include "../include/overlay_scanner.h"
#include "../include/anti_debug.h"
#include "../include/anti_suspend.h"
#include "../include/injection_scanner.h"
#include "../include/logger.h"
#include "../include/utils.h"

// Fungsi export untuk Stud_PE seperti yang diminta
extern "C" __declspec(dllexport) void OblivionEye_Entry() {}

// Fungsi untuk scan berkala
void __stdcall ScanThread() {
    // Inisialisasi logger
    wchar_t gamePath[MAX_PATH];
    if (GetModuleFileNameW(NULL, gamePath, MAX_PATH)) {
        std::wstring logPath = gamePath;
        size_t pos = logPath.find_last_of(L"\\/");
        if (pos != std::wstring::npos) {
            logPath = logPath.substr(0, pos) + L"\\oblivioneye.log";
        }
        else {
            logPath = L"oblivioneye.log";
        }

        Logger::Initialize(logPath);
        Logger::SetLogLevel(LOGGER_DEBUG);
        Logger::Info(L"Oblivion Eye Anti-Cheat initialized");
    }
    else {
        // Jika tidak bisa mendapatkan path game, gunakan path default
        Logger::Initialize(L"oblivioneye.log");
        Logger::SetLogLevel(LOGGER_DEBUG);
        Logger::Info(L"Oblivion Eye Anti-Cheat initialized (default path)");
    }

    // Tambahkan delay awal untuk memastikan game sudah benar-benar berjalan
    Sleep(2000);

    // Inisialisasi monitoring thread
    AntiSuspend::InitializeThreadMonitoring();

    while (true) {
        // Cek proses berbahaya
        if (ProcessWatcher::CheckBlacklistedProcesses()) {
            Logger::CheatDetected(L"Blacklisted Process", L"Blacklisted process detected");
            Utils::CloseGame();
            break;
        }

        // Cek overlay windows
        if (OverlayScanner::DetectOverlayWindows()) {
            Logger::CheatDetected(L"Overlay Window", L"Suspicious overlay window detected");
            Utils::CloseGame();
            break;
        }

        // Cek apakah sedang di-debug
        if (AntiDebug::IsDebugged()) {
            Logger::CheatDetected(L"Debugger", L"Debugger or analysis tool detected");
            Utils::CloseGame();
            break;
        }

        // Cek apakah thread di-suspend
        if (AntiSuspend::IsThreadSuspended()) {
            Logger::CheatDetected(L"Suspended Thread", L"Game thread was suspended");
            Utils::CloseGame();
            break;
        }

        // Cek apakah ada modul yang di-inject
        if (InjectionScanner::DetectInjectedModules()) {
            Logger::CheatDetected(L"Injected Module", L"Suspicious module injection detected");
            Utils::CloseGame();
            break;
        }

        Sleep(5000); // Scan setiap 5 detik
    }

    // Hentikan monitoring thread
    AntiSuspend::StopThreadMonitoring();

    // Pastikan semua log tertulis
    Logger::Flush();
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
    {
        // HANYA buat thread untuk scan berkala di sini
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ScanThread, NULL, 0, NULL);
        break;
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}