#include "../pch.h"
#include "../include/Utils.h"
#include "../include/Logger.h"
#include "../include/EventReporter.h"
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <algorithm>

namespace OblivionEye {
    std::wstring ToLower(const std::wstring& s) {
        std::wstring r = s;
        std::transform(r.begin(), r.end(), r.begin(), ::towlower);
        return r;
    }

    std::wstring GetProcessImageName(DWORD pid) {
        std::wstring name;
        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!h) return name;
        wchar_t path[MAX_PATH] = {};
        DWORD size = MAX_PATH;
        if (QueryFullProcessImageNameW(h, 0, path, &size)) {
            // Ambil filename saja
            const wchar_t* lastBackslash = wcsrchr(path, L'\\');
            name = lastBackslash ? (lastBackslash + 1) : path;
        }
        CloseHandle(h);
        return name;
    }

    void ShowDetectionAndExit(const std::wstring& reason) {
        Log(L"Deteksi cheat: " + reason);
        EventReporter::SendDetection(L"OblivionEye", reason);
        MessageBoxW(nullptr, (L"Cheat terdeteksi: " + reason + L"\nRagnarok akan ditutup.").c_str(), L"Oblivion Eye", MB_OK | MB_ICONERROR | MB_TOPMOST);
        ExitProcess(0);
    }
}
