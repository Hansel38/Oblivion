#include "../include/utils.h"
#include <TlHelp32.h>
#include <string>
#include <Windows.h>

namespace Utils {
    bool IsProcessRunning(const std::wstring& processName) {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            return false;
        }

        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(PROCESSENTRY32W);

        if (Process32FirstW(hSnapshot, &pe)) {
            do {
                if (_wcsicmp(pe.szExeFile, processName.c_str()) == 0) {
                    CloseHandle(hSnapshot);
                    return true;
                }
            } while (Process32NextW(hSnapshot, &pe));
        }

        CloseHandle(hSnapshot);
        return false;
    }

    void ShowCheatDetectedMessage(const std::wstring& cheatType) {
        // Buat pesan yang lebih informatif
        std::wstring message = L"Oblivion Eye Anti-Cheat mendeteksi aktivitas mencurigakan!\n\n";
        message += L"Jenis cheat terdeteksi: " + cheatType + L"\n\n";
        message += L"Sistem keamanan kami telah menghentikan koneksi Anda.\n";
        message += L"Jika Anda yakin ini adalah kesalahan, hubungi administrator game.";

        // Tampilkan messagebox dengan ikon error
        MessageBoxW(nullptr,
            message.c_str(),
            L"Oblivion Eye - Cheat Terdeteksi",
            MB_ICONERROR | MB_OK | MB_TOPMOST);
    }

    void CloseGame() {
        // Dapatkan handle window game
        HWND hwnd = FindWindowW(L"ROClientClass", nullptr);

        // Tampilkan messagebox tergantung pada jenis cheat yang terdeteksi
        if (hwnd) {
            // Kita tidak tahu jenis cheatnya di sini, jadi kita coba deteksi
            if (AntiDebug::IsDebugged()) {
                ShowCheatDetectedMessage(L"Debugger/Analisis");
            }
            else if (ProcessWatcher::CheckBlacklistedProcesses()) {
                ShowCheatDetectedMessage(L"Software Cheat (Cheat Engine, dll)");
            }
            else if (OverlayScanner::DetectOverlayWindows()) {
                ShowCheatDetectedMessage(L"Overlay/ESP");
            }
            else if (AntiSuspend::IsThreadSuspended()) {
                ShowCheatDetectedMessage(L"Thread Suspended");
            }
            else if (InjectionScanner::DetectInjectedModules()) {
                ShowCheatDetectedMessage(L"Modul Terinjeksi");
            }
            else if (MemoryScanner::ScanMemoryForSignatures()) {
                ShowCheatDetectedMessage(L"Signature Mencurigakan");
            }
            else {
                ShowCheatDetectedMessage(L"Aktivitas Mencurigakan");
            }

            // Kirim WM_CLOSE ke window game
            PostMessageW(hwnd, WM_CLOSE, 0, 0);
        }
        // Jika tidak berhasil, tutup proses
        else {
            // Tampilkan messagebox umum
            ShowCheatDetectedMessage(L"Sistem Keamanan Aktif");

            HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, GetCurrentProcessId());
            if (hProcess) {
                TerminateProcess(hProcess, 1);
                CloseHandle(hProcess);
            }
        }
    }

    std::wstring GetProcessName(DWORD processId) {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
        if (!hProcess)
            return L"";

        wchar_t buffer[MAX_PATH] = { 0 };
        DWORD size = sizeof(buffer) / sizeof(buffer[0]);

        if (QueryFullProcessImageNameW(hProcess, 0, buffer, &size) == 0) {
            CloseHandle(hProcess);
            return L"";
        }

        CloseHandle(hProcess);

        // Ambil nama file dari path
        std::wstring fullPath(buffer);
        size_t pos = fullPath.find_last_of(L"\\/");
        if (pos != std::wstring::npos) {
            return fullPath.substr(pos + 1);
        }

        return fullPath;
    }
}