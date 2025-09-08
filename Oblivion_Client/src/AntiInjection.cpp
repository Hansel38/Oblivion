#include "../pch.h"
#include "../include/AntiInjection.h"
#include "../include/ModuleBlacklist.h"
#include "../include/Utils.h"
#include "../include/Logger.h"
#include "../include/EventReporter.h"
#include "../include/PublisherWhitelist.h"
#include <windows.h>
#include <psapi.h>
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

    bool AntiInjection::ScanModules() {
        HMODULE mods[1024] = {};
        DWORD needed = 0;
        if (!EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &needed))
            return false;
        int count = needed / sizeof(HMODULE);
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
            // 2) Whitelist publisher (opsional): jika daftar trusted tidak kosong, modul harus signed-by-trusted
            const auto& trusted = PublisherWhitelist::GetTrusted();
            if (!trusted.empty()) {
                auto path = GetModuleFilePath(mods[i]);
                if (!PublisherWhitelist::IsFileSignedByTrusted(path)) {
                    EventReporter::SendDetection(L"AntiInjection", L"Unsigned or untrusted publisher: " + path);
                    ShowDetectionAndExit(L"Module unsigned/Untrusted: " + path);
                    return true;
                }
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
