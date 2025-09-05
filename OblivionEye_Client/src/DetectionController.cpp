#include "../include/DetectionController.h"
#include "../include/Logger.h"
#include <atomic>
#include <mutex>
#include <windows.h>
#include <tlhelp32.h>
#include <shellapi.h>
#include <string>
#include <algorithm>

namespace DetectionController {
    static std::atomic<bool> g_stopRequested{false};
    static std::atomic<bool> g_detectionTriggered{false};
    static std::string g_reason; 
    static std::mutex g_reasonMutex;

    static std::string ToLowerCopy(std::string s) {
        std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return (char)std::tolower(c); });
        return s;
    }

    static std::string ProcessNameLower(const PROCESSENTRY32 &pe) {
#ifdef UNICODE
        int needed = WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, nullptr, 0, nullptr, nullptr);
        if (needed <= 0) return {};
        std::string out(needed - 1, '\0'); // exclude null terminator
        WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, out.data(), needed - 1, nullptr, nullptr);
        return ToLowerCopy(out);
#else
        return ToLowerCopy(std::string(pe.szExeFile));
#endif
    }

    static void LaunchExternalMessageBox(const std::string& reason) {
        // Use ShellExecute with PowerShell; avoids mutable buffer needed by CreateProcessA.
        std::string msg = "Client ditutup karena terdeteksi cheat.\\nReason: " + reason;
        // Escape single quotes for PowerShell single-quoted string
        std::string esc = msg; size_t pos = 0; while ((pos = esc.find("'", pos)) != std::string::npos) { esc.insert(pos, "'"); pos += 2; }
        std::string psArgs = "-NoProfile -WindowStyle Hidden -Command \"Add-Type -AssemblyName PresentationFramework;[System.Windows.MessageBox]::Show('" + esc + "','Oblivion Eye','OK','Error')\"";
        HINSTANCE hInst = ShellExecuteA(nullptr, "open", "powershell.exe", psArgs.c_str(), nullptr, SW_HIDE);
        if ((UINT_PTR)hInst <= 32) {
            Logger::Log(LOG_WARNING, "ShellExecuteA PowerShell failed for message box");
        }
    }

    static void KillAllRRO(const std::string& targetLower) {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) return;
        PROCESSENTRY32 pe{}; pe.dwSize = sizeof(pe);
        if (Process32First(snap, &pe)) {
            do {
                std::string name = ProcessNameLower(pe);
                if (name == targetLower) {
                    HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                    if (h) { TerminateProcess(h, 0); CloseHandle(h); }
                }
            } while (Process32Next(snap, &pe));
        }
        CloseHandle(snap);
    }

    void Initialize() {
        g_stopRequested = false;
        g_detectionTriggered = false;
        std::lock_guard<std::mutex> lk(g_reasonMutex);
        g_reason.clear();
    }

    void RequestShutdown() { g_stopRequested = true; }

    void ReportDetection(const std::string& reason) {
        bool expected = false;
        if (!g_detectionTriggered.compare_exchange_strong(expected, true)) return;
        {
            std::lock_guard<std::mutex> lk(g_reasonMutex);
            g_reason = reason;
        }
        Logger::Log(LOG_DETECTED, "Detection triggered: " + reason);
        g_stopRequested = true;

        const std::string targetLower = "rro.exe";
        // Spawn external message BEFORE terminating this process (so it appears after close)
        LaunchExternalMessageBox(reason);
        // Kill all instances including self
        KillAllRRO(targetLower);
        // Force self exit (in case terminate race)
        ExitProcess(0);
    }

    bool IsStopRequested() { return g_stopRequested.load(); }
    bool IsDetectionTriggered() { return g_detectionTriggered.load(); }
    std::string GetDetectionReason() { std::lock_guard<std::mutex> lk(g_reasonMutex); return g_reason; }
}
