#include "../pch.h"
#include "../include/AntiInjection.h"
#include "../include/Logger.h"
#include "../include/EventReporter.h"
#include "../include/PublisherWhitelist.h"
#include "../include/ModuleBlacklist.h"
#include "../include/Utils.h"
#include <windows.h>
#include <psapi.h>
#include <thread>
#include <string>

#pragma comment(lib, "psapi.lib")

namespace OblivionEye {

    AntiInjection& AntiInjection::Instance() { static AntiInjection s; return s; }

    static std::wstring GetModuleBaseNameLower(HMODULE h) {
        wchar_t name[256] = {}; GetModuleBaseNameW(GetCurrentProcess(), h, name, 255); std::wstring n = name; for (auto& c : n) c = (wchar_t)towlower(c); return n; }
    static std::wstring GetModuleFilePath(HMODULE h) { wchar_t path[MAX_PATH] = {}; GetModuleFileNameW(h, path, MAX_PATH); return path; }

    static bool IsPathSuspicious(const std::wstring& p) {
        std::wstring low = p; for (auto& c : low) c = (wchar_t)towlower(c);
        if (low.find(L"\\temp") != std::wstring::npos) return true;
        if (low.find(L"\\appdata\\local\\temp") != std::wstring::npos) return true;
        wchar_t profile[MAX_PATH]; DWORD sz = MAX_PATH; if (GetEnvironmentVariableW(L"USERPROFILE", profile, sz)) {
            std::wstring down = std::wstring(profile) + L"\\downloads"; for (auto& c : down) c = (wchar_t)towlower(c);
            if (low.find(down) == 0) return true;
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
            for (const auto& bad : GetBlacklistedModuleNames()) {
                std::wstring lowBad = bad; for (auto& c : lowBad) c = (wchar_t)towlower(c);
                if (name == lowBad) {
                    EventReporter::SendDetection(L"AntiInjection", name);
                    ShowDetectionAndExit(std::wstring(L"Injected module: ") + name);
                    return true;
                }
            }
            auto path = GetModuleFilePath(mods[i]);
            if (!trusted.empty()) {
                if (!PublisherWhitelist::IsFileSignedByTrusted(path)) {
                    EventReporter::SendDetection(L"AntiInjection", L"Unsigned or untrusted publisher: " + path);
                    ShowDetectionAndExit(L"Module unsigned/Untrusted: " + path);
                    return true;
                }
            }
            if (trusted.empty() && IsPathSuspicious(path)) {
                EventReporter::SendDetection(L"AntiInjection", L"Suspicious path: " + path);
                ShowDetectionAndExit(L"Module from suspicious path: " + path);
                return true;
            }
        }
        return false;
    }

    void AntiInjection::Tick() {
        ScanModules();
    }
}
