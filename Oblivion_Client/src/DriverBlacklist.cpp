#include "../pch.h"
#include "../include/DriverBlacklist.h"
#include <algorithm>

namespace OblivionEye {
namespace {
    std::vector<std::wstring> g_drv = {
        L"dbk32.sys",       // Cheat Engine driver
        L"dbk64.sys",       // CE 64-bit
        L"ksdumper.sys",
        L"faceit.sys",
        L"easyanticheat.sys",
        L"capcom.sys"
    };

    std::wstring ToLowerCopy(const std::wstring &s) {
        std::wstring r = s; std::transform(r.begin(), r.end(), r.begin(), ::towlower); return r;
    }
}

const std::vector<std::wstring> &GetBlacklistedDriverNames() { return g_drv; }

void AddBlacklistedDriverName(const std::wstring &name) {
    auto low = ToLowerCopy(name);
    if (std::find(g_drv.begin(), g_drv.end(), low) == g_drv.end())
        g_drv.push_back(low);
}

void ClearBlacklistedDriverNames() { g_drv.clear(); }
}
