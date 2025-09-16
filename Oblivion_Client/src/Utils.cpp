#include "../pch.h"
#include "../include/Utils.h"
#include "../include/Logger.h"
#include "../include/EventReporter.h"
#include "../include/Config.h" // diperlukan untuk OblivionEye::Config::MODSEC_AUDIT_MODE_DEFAULT
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

    bool IsAuditMode() {
        static int cached = -1; // -1 unknown, 0 false, 1 true
        if (cached == -1) {
            cached = OblivionEye::Config::MODSEC_AUDIT_MODE_DEFAULT ? 1 : 0;
            wchar_t buf[16]; DWORD len = GetEnvironmentVariableW(L"MODSEC_AUDIT", buf, 16);
            if (len && len < 16) {
                if (buf[0] == L'1' || buf[0]==L'T' || buf[0]==L't' || buf[0]==L'Y' || buf[0]==L'y') cached = 1;
                else cached = 0;
            }
        }
        return cached == 1;
    }

    void ShowDetectionAndExit(const std::wstring& reason) {
        Log(L"Deteksi cheat: " + reason + (IsAuditMode() ? L" (AUDIT MODE)" : L""));
        EventReporter::SendDetection(L"OblivionEye", reason + (IsAuditMode() ? L" (AUDIT)" : L""));
        if (IsAuditMode()) {
            // In audit mode we do not terminate; optionally show a less intrusive notification
            OutputDebugStringW((L"[AUDIT] Cheat detection (no terminate): " + reason + L"\n").c_str());
            return;
        }
        MessageBoxW(nullptr, (L"Cheat terdeteksi: " + reason + L"\nRagnarok akan ditutup.").c_str(), L"Oblivion Eye", MB_OK | MB_ICONERROR | MB_TOPMOST);
        ExitProcess(0);
    }
}
