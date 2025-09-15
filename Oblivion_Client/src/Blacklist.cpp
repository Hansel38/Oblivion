#include "../pch.h"
#include "../include/Blacklist.h"
#include <algorithm>

namespace OblivionEye {
namespace {
    std::vector<std::wstring> g_blacklisted = {
        L"cheatengine.exe",
        L"cheat engine.exe",
        L"cheatengine-x86_64.exe",
        L"openkore.exe",
        L"wpe.exe",
        L"rpe.exe",
        L"processhacker.exe",
        L"ollydbg.exe",
        L"x64dbg.exe",
        L"ida64.exe",
        L"ida.exe"
    };

    std::wstring ToLowerCopy(const std::wstring &s) {
        std::wstring r = s;
        std::transform(r.begin(), r.end(), r.begin(), ::towlower);
        return r;
    }
}

const std::vector<std::wstring> &GetBlacklistedProcessNames() { return g_blacklisted; }

void AddBlacklistedProcessName(const std::wstring &name) {
    auto low = ToLowerCopy(name);
    if (std::find(g_blacklisted.begin(), g_blacklisted.end(), low) == g_blacklisted.end())
        g_blacklisted.push_back(low);
}

void ClearBlacklistedProcessNames() { g_blacklisted.clear(); }
}
