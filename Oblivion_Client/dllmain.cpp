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

// fungsi export dari stud_pe
extern "C" __declspec(dllexport) void OblivionEye_Entry() {}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        // Terapkan proteksi handle sebelum modul lain start
        OblivionEye::HandleProtection::Apply();
        OblivionEye::RuntimeStats::Instance().SetStartTick();

        // Seed publisher whitelist (contoh). TODO: sesuaikan publisher resmi Anda
        // OblivionEye::PublisherWhitelist::AddTrusted(L"microsoft corporation");
        // OblivionEye::PublisherWhitelist::AddTrusted(L"gravity co., ltd.");

        // Daftarkan main thread agar diproteksi AntiSuspend
        OblivionEye::RegisterThreadId(GetCurrentThreadId());

        // Start PipeClient untuk komunikasi ke server (Named Pipe)
        OblivionEye::PipeClient::Instance().Start(L"\\\\.\\pipe\\OblivionEye");
        // Start PipeCommandClient untuk menerima perintah dari server
        OblivionEye::PipeCommandClient::Instance().Start(L"\\\\.\\pipe\\OblivionEyeCmd");

        // Tambahkan path file kritikal untuk verifikasi signature (contoh)
        // OblivionEye::DigitalSignatureScanner::Instance().AddCriticalPath(L"C:\\Game\\RRO.exe");

        OblivionEye::ProcessWatcher::Instance().Start();
        OblivionEye::Heartbeat::Instance().Start(10000); // 10 detik
        OblivionEye::OverlayScanner::Instance().Start(2000); // 2 detik
        OblivionEye::DriverScanner::Instance().Start(10000); // 10 detik, ringan
        OblivionEye::AntiDebug::Instance().Start(3000); // 3 detik
        OblivionEye::AntiSuspend::Instance().Start(2000); // 2 detik
        OblivionEye::AntiInjection::Instance().Start(5000); // 5 detik
        OblivionEye::DigitalSignatureScanner::Instance().Start(15000); // 15 detik
        OblivionEye::AntiTestMode::Instance().Start(15000); // 15 detik
        OblivionEye::SignatureScanner::Instance().Start(20000); // 20 detik
        OblivionEye::HijackedThreadDetector::Instance().Start(7000); // 7 detik
        OblivionEye::IATHookChecker::Instance().Start(30000); // 30 detik
        OblivionEye::PrologHookChecker::Instance().Start(45000); // 45 detik (lambat, berat)
        OblivionEye::NtdllIntegrity::Instance().Start(60000); // 60 detik (1 menit)
        OblivionEye::Kernel32Integrity::Instance().Start(60000); // 60 detik (1 menit)
        OblivionEye::User32Integrity::Instance().Start(90000); // 90 detik (1.5 menit)
        OblivionEye::Gdi32Integrity::Instance().Start(90000); // 90 detik (1.5 menit)
        OblivionEye::TestModeSpoofChecker::Instance().Start(30000); // 30 detik
        break;
    case DLL_THREAD_ATTACH:
        OblivionEye::RegisterThreadId(GetCurrentThreadId());
        break;
    case DLL_THREAD_DETACH:
        OblivionEye::UnregisterThreadId(GetCurrentThreadId());
        break;
    case DLL_PROCESS_DETACH:
        OblivionEye::Gdi32Integrity::Instance().Stop();
        OblivionEye::User32Integrity::Instance().Stop();
        OblivionEye::Kernel32Integrity::Instance().Stop();
        OblivionEye::NtdllIntegrity::Instance().Stop();
        OblivionEye::PrologHookChecker::Instance().Stop();
        OblivionEye::PipeCommandClient::Instance().Stop();
        OblivionEye::TcpClient::Instance().Stop();
        OblivionEye::TestModeSpoofChecker::Instance().Stop();
        OblivionEye::IATHookChecker::Instance().Stop();
        OblivionEye::HijackedThreadDetector::Instance().Stop();
        OblivionEye::PipeClient::Instance().Stop();
        OblivionEye::SignatureScanner::Instance().Stop();
        OblivionEye::AntiTestMode::Instance().Stop();
        OblivionEye::DigitalSignatureScanner::Instance().Stop();
        OblivionEye::AntiInjection::Instance().Stop();
        OblivionEye::AntiSuspend::Instance().Stop();
        OblivionEye::AntiDebug::Instance().Stop();
        OblivionEye::DriverScanner::Instance().Stop();
        OblivionEye::OverlayScanner::Instance().Stop();
        OblivionEye::Heartbeat::Instance().Stop();
        OblivionEye::ProcessWatcher::Instance().Stop();
        break;
    }
    return TRUE;
}

