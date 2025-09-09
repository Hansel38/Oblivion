#include "../pch.h"
#include "../include/AntiInjection.h"
#include "../include/ModuleBlacklist.h"
#include "../include/Utils.h"
#include "../include/Logger.h"
#include "../include/EventReporter.h"
#include "../include/PublisherWhitelist.h"
#include <windows.h>
#include <psapi.h>
#include <shlobj.h>
#include <vector>
#include <string>
#include <algorithm>
#include <thread>
#include <chrono>

#pragma comment(lib, "psapi.lib")

namespace OblivionEye {

    AntiInjection& AntiInjection::Instance() { static AntiInjection s; return s; }

    static std::wstring GetModuleBaseNameLower(HMODULE mod) {
        wchar_t name[MAX_PATH] = {};
        if (GetModuleBaseNameW(GetCurrentProcess(), mod, name, MAX_PATH)) {
            std::wstring low = ToLower(name);
            return low;
        }
        return L"";
    }

    static std::wstring GetModuleFilePath(HMODULE mod) {
        wchar_t path[MAX_PATH] = {};
        GetModuleFileNameW(mod, path, MAX_PATH);
        return path;
    }

    static bool IsPathSuspicious(const std::wstring& path) {
        if (path.empty()) return false;
        wchar_t tempPath[MAX_PATH]; GetTempPathW(MAX_PATH, tempPath);
        std::wstring tempL = ToLower(tempPath);
        std::wstring pL = ToLower(path);
        // %TEMP%
        if (pL.find(tempL) == 0) return true;
        // %APPDATA%
        wchar_t appdata[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_APPDATA, nullptr, 0, appdata))) {
            std::wstring appL = ToLower(appdata);
            if (pL.find(appL) == 0) return true;
        }
        // User profile Downloads
        wchar_t profile[MAX_PATH]; DWORD sz = MAX_PATH; if (GetEnvironmentVariableW(L"USERPROFILE", profile, sz)) {
            std::wstring down = ToLower(std::wstring(profile) + L"\\downloads");
            if (pL.find(down) == 0) return true;
        }
        return false;
    }

    bool AntiInjection::ScanModules() {
        HMODULE mods[1024] = {};
        DWORD needed = 0;
        if (!EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &needed))
            return false;
        int count = needed / sizeof(HMODULE);
        const auto& trusted = PublisherWhitelist::GetTrusted();
        for (int i = 0; i < count; ++i) {
            std::wstring name = GetModuleBaseNameLower(mods[i]);
            if (name.empty()) continue;
            // 1) Blacklist check
            for (const auto& bad : GetBlacklistedModuleNames()) {
                if (name == ToLower(bad)) {
                    EventReporter::SendDetection(L"AntiInjection", name);
                    ShowDetectionAndExit(std::wstring(L"Injected module: ") + name);
                    return true;
                }
            }
            auto path = GetModuleFilePath(mods[i]);
            // 2) Whitelist publisher (opsional)
            if (!trusted.empty()) {
                if (!PublisherWhitelist::IsFileSignedByTrusted(path)) {
                    EventReporter::SendDetection(L"AntiInjection", L"Unsigned or untrusted publisher: " + path);
                    ShowDetectionAndExit(L"Module unsigned/Untrusted: " + path);
                    return true;
                }
            }
            // 3) Suspicious path heuristik (hanya bila whitelist publisher kosong)
            if (trusted.empty() && IsPathSuspicious(path)) {
                EventReporter::SendDetection(L"AntiInjection", L"Suspicious path: " + path);
                ShowDetectionAndExit(L"Module from suspicious path: " + path);
                return true;
            }
        }
        return false;
    }

    void AntiInjection::Start(unsigned intervalMs) {
        if (m_running.exchange(true)) return;
        std::thread([this, intervalMs]() { Loop(intervalMs); }).detach();
    }

    void AntiInjection::Stop() { m_running = false; }

    void AntiInjection::Loop(unsigned intervalMs) {
        Log(L"AntiInjection start");
        while (m_running) {
            if (ScanModules()) return; 
            std::this_thread::sleep_for(std::chrono::milliseconds(intervalMs));
        }
        Log(L"AntiInjection stop");
    }
}
