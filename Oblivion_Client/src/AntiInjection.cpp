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
namespace {
    std::wstring ToLowerCopy(std::wstring s) {
        for (auto &c : s) c = static_cast<wchar_t>(towlower(c));
        return s;
    }

    std::wstring GetModuleBaseNameLower(HMODULE h) {
        wchar_t name[256] = {};
        if (!GetModuleBaseNameW(GetCurrentProcess(), h, name, 255))
            return {};
        return ToLowerCopy(name);
    }

    std::wstring GetModuleFilePath(HMODULE h) {
        wchar_t path[MAX_PATH] = {};
        if (GetModuleFileNameW(h, path, MAX_PATH))
            return path;
        return {};
    }

    bool IsPathSuspicious(const std::wstring &p) {
        std::wstring low = ToLowerCopy(p);
        if (low.find(L"\\temp") != std::wstring::npos)
            return true;
        if (low.find(L"\\appdata\\local\\temp") != std::wstring::npos)
            return true;
        wchar_t profile[MAX_PATH]; DWORD sz = MAX_PATH;
        if (GetEnvironmentVariableW(L"USERPROFILE", profile, sz)) {
            std::wstring down = ToLowerCopy(std::wstring(profile) + L"\\downloads");
            if (low.rfind(down, 0) == 0) // starts with
                return true;
        }
        return false;
    }

    bool IsBlacklistedName(const std::wstring &modLower) {
        for (const auto &bad : GetBlacklistedModuleNames()) {
            if (modLower == ToLowerCopy(bad))
                return true;
        }
        return false;
    }

    bool EnforcePublisherWhitelist(const std::wstring &path) {
        if (PublisherWhitelist::GetTrusted().empty())
            return true; // no whitelist configured -> skip
        if (PublisherWhitelist::IsFileSignedByTrusted(path))
            return true;
        EventReporter::SendDetection(L"AntiInjection", L"Unsigned or untrusted publisher: " + path);
        ShowDetectionAndExit(L"Module unsigned/Untrusted: " + path);
        return false;
    }
    // Probe artefak device Cheat Engine (dbk driver) tanpa menambah detector baru terpisah.
    // Dilakukan jarang (cooldown) untuk menghindari overhead.
    unsigned long long g_lastDbkProbe = 0;
    constexpr unsigned long long DBK_PROBE_INTERVAL_MS = 15000; // 15s
    const wchar_t* g_dbkDevices[] = { L"\\\\.\\DBKKernel", L"\\\\.\\DBKProc", L"\\\\.\\DBKPhys" };

    void ProbeDbkArtifacts() {
        unsigned long long now = GetTickCount64();
        if (now - g_lastDbkProbe < DBK_PROBE_INTERVAL_MS) return;
        g_lastDbkProbe = now;
        for (auto dev : g_dbkDevices) {
            HANDLE h = CreateFileW(dev, GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (h != INVALID_HANDLE_VALUE) {
                CloseHandle(h);
                EventReporter::SendDetection(L"AntiInjection", std::wstring(L"DeviceArtifact ") + dev);
                ShowDetectionAndExit(std::wstring(L"Device artifact detected: ") + dev);
                return; // proses sudah dihentikan
            }
        }
    }
}

AntiInjection &AntiInjection::Instance() { static AntiInjection s; return s; }

bool AntiInjection::ScanModules() {
    HMODULE mods[1024] = {};
    DWORD needed = 0;
    if (!EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &needed)) {
        Log(L"AntiInjection: EnumProcessModules gagal");
        return false;
    }

    int count = static_cast<int>(needed / sizeof(HMODULE));
    bool usingWhitelist = !PublisherWhitelist::GetTrusted().empty();

    for (int i = 0; i < count; ++i) {
        std::wstring nameLower = GetModuleBaseNameLower(mods[i]);
        if (nameLower.empty())
            continue;

        if (IsBlacklistedName(nameLower)) {
            EventReporter::SendDetection(L"AntiInjection", nameLower);
            ShowDetectionAndExit(std::wstring(L"Injected module: ") + nameLower);
            return true;
        }

        auto path = GetModuleFilePath(mods[i]);
        if (path.empty())
            continue;

        if (usingWhitelist) {
            if (!EnforcePublisherWhitelist(path))
                return true; // function already exited the process if violation
        } else if (IsPathSuspicious(path)) {
            EventReporter::SendDetection(L"AntiInjection", L"Suspicious path: " + path);
            ShowDetectionAndExit(L"Module from suspicious path: " + path);
            return true;
        }
    }
    return false;
}

void AntiInjection::Tick() {
    ScanModules();
    ProbeDbkArtifacts();
}

// (Tick memanggil ProbeDbkArtifacts)
}
