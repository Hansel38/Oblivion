#include "../pch.h"
#include "../include/ModuleBlacklist.h"
#include <algorithm>

namespace OblivionEye {
    static std::vector<std::wstring> g_modules = {
        L"dbghelp.dll",
        L"scylla.dll",
        L"xinput1_3.dll",
        L"cheatengine-i386.dll",
        L"cheatengine-x86_64.dll",
        L"speedhack-i386.dll"
    };

    const std::vector<std::wstring>& GetBlacklistedModuleNames() { return g_modules; }

    static std::wstring ToLower(const std::wstring& s) {
        std::wstring r = s;
        std::transform(r.begin(), r.end(), r.begin(), ::towlower);
        return r;
    }

    void AddBlacklistedModuleName(const std::wstring& name) {
        auto low = ToLower(name);
        if (std::find(g_modules.begin(), g_modules.end(), low) == g_modules.end())
            g_modules.push_back(low);
    }

    void ClearBlacklistedModuleNames() { g_modules.clear(); }
}
