#include <windows.h>
#include <thread>
#include "../include/ServerCommunication.h"
#include "../include/ProcessWatcher.h"
#include "../include/OverlayScanner.h"
#include "../include/AntiDebug.h"
#include "../include/AntiSuspend.h"
#include "../include/InjectionScanner.h"
#include "../include/SignatureValidator.h"
#include "../include/MemoryScanner.h"
#include "../include/HijackDetector.h"
#include "../include/IATHookScanner.h"
#include "../include/HWIDSystem.h"
#include "../include/FileIntegrityChecker.h"
#include "../include/Logger.h"
#include "../include/Config.h"
#include "../include/DetectionController.h"
#include <atomic>
#include <vector>

static HANDLE mainThreadHandle = nullptr;

static void GracefulStopAll() {
    // Stop background subsystems
    ShutdownServerSession();
    StopAntiSuspendThread();
}

DWORD WINAPI MainThread(LPVOID) {
    Config::Load();
    auto& cfg = Config::Get();
    mainThreadHandle = GetCurrentThread();
    Logger::Initialize(cfg.logFileName);
    DetectionController::Initialize();
    Logger::Log(LOG_INFO, "Oblivion Eye DLL loaded");
    LogHWID();
    std::string currentHWID = GenerateHWID();
    if (!PerformServerValidation(currentHWID)) {
        DetectionController::ReportDetection("Server-side validation failed");
    }
    if (DetectionController::IsDetectionTriggered()) {
        Logger::Log(LOG_INFO, "Early detection -> skipping scanners");
        GracefulStopAll();
        Logger::Close();
        return 0;
    }
    Logger::Log(LOG_INFO, "Server-side validation passed (persistent session).");
    StartAntiSuspendThread(mainThreadHandle);

    std::thread processThread(ContinuousProcessScan);
    std::thread overlayThread(ContinuousOverlayScan);
    std::thread antiDebugThread(ContinuousAntiDebugScan);
    std::thread injectionThread(ContinuousInjectionScan);
    std::thread signatureThread(ContinuousSignatureValidation);
    std::thread memoryThread(ContinuousMemoryScan);
    std::thread hijackThread(ContinuousHijackDetection);
    std::thread iatHookThread(ContinuousIATHookScan);
    std::thread fileIntegrityThread(ContinuousFileIntegrityCheck);

    // Main supervisory loop: tunggu sinyal stop/detection
    while (!DetectionController::IsStopRequested()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    Logger::Log(LOG_INFO, "Stop requested (" + (DetectionController::IsDetectionTriggered() ? std::string("detection: ") + DetectionController::GetDetectionReason() : std::string("manual/unload")) + ")");

    GracefulStopAll();

    // Bergabung dengan semua thread scanner
    auto joinSafe = [](std::thread &t, const char* name){
        if (t.joinable()) {
            try { t.join(); }
            catch (...) { Logger::Log(LOG_WARNING, std::string("Failed to join ") + name); }
        }
    };

    joinSafe(processThread, "ProcessThread");
    joinSafe(overlayThread, "OverlayThread");
    joinSafe(antiDebugThread, "AntiDebugThread");
    joinSafe(injectionThread, "InjectionThread");
    joinSafe(signatureThread, "SignatureThread");
    joinSafe(memoryThread, "MemoryThread");
    joinSafe(hijackThread, "HijackThread");
    joinSafe(iatHookThread, "IATHookThread");
    joinSafe(fileIntegrityThread, "FileIntegrityThread");

    Logger::Log(LOG_INFO, "All scanner threads joined");
    Logger::Log(LOG_INFO, "Main thread exiting");
    Logger::Close();
    return 0;
}

BOOL APIENTRY DllMain(HMODULE, DWORD ul_reason_for_call, LPVOID) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        CreateThread(NULL, 0, MainThread, NULL, 0, NULL);
        break;
    case DLL_PROCESS_DETACH:
        // Minta shutdown – main supervisory loop akan mendeteksi dan join threads.
        DetectionController::RequestShutdown();
        break;
    }
    return TRUE;
}

extern "C" __declspec(dllexport) void OblivionEye_Entry() {}