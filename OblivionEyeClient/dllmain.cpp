#include <windows.h>
#include <psapi.h>
#include "include/ProcessWatcher.h"
#include "include/OverlayScanner.h"
#include "include/AntiDebug.h"
#include "include/InjectionScanner.h"
#include "include/MemoryScanner.h"
#include "include/FileIntegrity.h"
#include "include/HWIDSystem.h"
#include "include/NetworkClient.h" // Tambahkan ini
#include "include/Logger.h"
#include <thread>

// Fungsi alert langsung close
void TriggerAlertAndExit(const char* msg) {
    Logger::LogDetected(msg);
    Logger::Close();
    FatalAppExitA(0, msg);
}

void OblivionEye_Main() {
    Logger::Log("=== OblivionEye_Main Started ===");

    // === File Integrity Check saat startup ===
    if (FileIntegrity::IsFileIntegrityCompromised()) {
        TriggerAlertAndExit("File integrity check failed! Game will close.");
        return;
    }

    // === Generate HWID ===
    Logger::Log("Generating HWID...");
    std::string hwid = HWIDSystem::GenerateHWID();
    Logger::Log("Client HWID: " + hwid);

    // === Kirim ke Server ===
    Logger::Log("Sending HWID to server...");
    if (!NetworkClient::SendHWIDToServer(hwid)) {
        TriggerAlertAndExit("HWID rejected by server! Game will close.");
        return;
    }

    Logger::Log("Server validation passed. Continuing with scans...");

    // === Scan sekali saat startup - Process ===
    if (ProcessWatcher::IsBlacklistedProcessRunning()) {
        TriggerAlertAndExit("Cheat process detected! Game will close.");
        return;
    }

    // === Scan sekali saat startup - Overlay ===
    if (OverlayScanner::IsOverlayDetected()) {
        TriggerAlertAndExit("Overlay detected! Game will close.");
        return;
    }

    // === Scan sekali saat startup - Anti-Debug ===
    if (AntiDebug::IsDebuggerDetected()) {
        TriggerAlertAndExit("Debugger detected! Game will close.");
        return;
    }

    // === Scan sekali saat startup - Injection ===
    if (InjectionScanner::IsInjectedDllDetected()) {
        TriggerAlertAndExit("Injected DLL detected! Game will close.");
        return;
    }

    // === Scan sekali saat startup - Memory Tampering ===
    if (MemoryScanner::IsMemoryTampered()) {
        TriggerAlertAndExit("Memory tampering detected! Game will close.");
        return;
    }

    Logger::Log("=== Initial scans completed ===");

    // === Loop scanning berkala ===
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

        Sleep(2000); // Tunggu 2 detik sebelum scan berikutnya
    }
}

// Fungsi utama DLL
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        // Inisialisasi logger
        Logger::Log("DLL Attached - Starting OblivionEye...");
        // Jalankan fungsi utama di thread terpisah agar tidak blokir
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)OblivionEye_Main, NULL, 0, NULL);
        break;
    case DLL_PROCESS_DETACH:
        // Tutup logger saat DLL dilepas
        Logger::Close();
        break;
    }
    return TRUE;
}

// Fungsi yang diekspor untuk Stud_PE
// Harus sesuai dengan tutorial: nama fungsi yang bisa dipilih di Stud_PE
extern "C" __declspec(dllexport) void OblivionEye_Entry() {
    // Fungsi ini kosong karena semua logika ada di DllMain
    // Tapi perlu ada agar bisa di-import oleh Stud_PE
    return;
}