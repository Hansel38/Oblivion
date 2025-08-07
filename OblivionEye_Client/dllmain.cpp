#include <windows.h>
#include <thread>
// --- TAMBAHKAN INCLUDE UNTUK SERVER COMMUNICATION ---
#include "../include/ServerCommunication.h"
// -----------------------------------------------------
#include "../include/ProcessWatcher.h"
#include "../include/OverlayScanner.h"
#include "../include/AntiDebug.h"
#include "../include/AntiSuspend.h"
#include "../include/InjectionScanner.h"
#include "../include/SignatureValidator.h"
#include "../include/MemoryScanner.h"
#include "../include/HijackDetector.h"
#include "../include/IATHookScanner.h"
#include "../include/HWIDSystem.h" // Untuk LogHWID dan GenerateHWID
#include "../include/FileIntegrityChecker.h"
#include "../include/Logger.h"

static HANDLE mainThreadHandle = nullptr;

DWORD WINAPI MainThread(LPVOID lpParam) {
    // Simpan handle thread utama
    mainThreadHandle = GetCurrentThread();

    // Inisialisasi logger
    Logger::Initialize("oblivion_eye.log");
    Logger::Log(LOG_INFO, "Oblivion Eye DLL loaded");

    // === GENERATE DAN LOG HWID ===
    LogHWID();
    // =============================

    // === TAMBAHKAN VALIDASI SERVER ===
    // Lakukan validasi server-side menggunakan modul terpisah
    std::string currentHWID = GenerateHWID(); // Dapatkan HWID yang sudah di-cache
    if (!PerformServerValidation(currentHWID)) {
        Logger::Log(LOG_DETECTED, "Server-side validation failed, closing client.");
        ExitProcess(0);
    }
    Logger::Log(LOG_INFO, "Server-side validation passed.");
    // =============================

    // Mulai thread anti-suspend untuk memantau thread utama
    StartAntiSuspendThread(mainThreadHandle);

    // Deklarasi semua thread di awal scope
    std::thread processThread;
    std::thread overlayThread;
    std::thread antiDebugThread;
    std::thread injectionThread;
    std::thread signatureThread;
    std::thread memoryThread;
    std::thread hijackThread;
    std::thread iatHookThread;
    std::thread fileIntegrityThread;

    // Buat dan jalankan thread scanning process
    processThread = std::thread(ContinuousProcessScan);

    // Buat dan jalankan thread scanning overlay
    overlayThread = std::thread(ContinuousOverlayScan);

    // Buat dan jalankan thread scanning anti-debug
    antiDebugThread = std::thread(ContinuousAntiDebugScan);

    // Buat dan jalankan thread scanning injection
    injectionThread = std::thread(ContinuousInjectionScan);

    // Buat dan jalankan thread signature validation
    signatureThread = std::thread(ContinuousSignatureValidation);

    // Buat dan jalankan thread memory signature scanning
    memoryThread = std::thread(ContinuousMemoryScan);

    // Buat dan jalankan thread hijacked thread detection
    hijackThread = std::thread(ContinuousHijackDetection);

    // Buat dan jalankan thread IAT hook scanning
    iatHookThread = std::thread(ContinuousIATHookScan);

    // Buat dan jalankan thread file integrity checking
    fileIntegrityThread = std::thread(ContinuousFileIntegrityCheck);

    // Tunggu semua thread selesai (jika diperlukan/dapat di-join)
    if (processThread.joinable()) processThread.join();
    if (overlayThread.joinable()) overlayThread.join();
    if (antiDebugThread.joinable()) antiDebugThread.join();
    if (injectionThread.joinable()) injectionThread.join();
    if (signatureThread.joinable()) signatureThread.join();
    if (memoryThread.joinable()) memoryThread.join();
    if (hijackThread.joinable()) hijackThread.join();
    if (iatHookThread.joinable()) iatHookThread.join();
    if (fileIntegrityThread.joinable()) fileIntegrityThread.join();

    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        // Buat thread baru untuk scanning
        CreateThread(NULL, 0, MainThread, NULL, 0, NULL);
        break;
    case DLL_PROCESS_DETACH:
        StopAntiSuspendThread();
        Logger::Log(LOG_INFO, "Oblivion Eye DLL unloaded");
        Logger::Close();
        break;
    }
    return TRUE;
}

// Fungsi ekspor untuk Stud_PE
extern "C" __declspec(dllexport) void OblivionEye_Entry() {}