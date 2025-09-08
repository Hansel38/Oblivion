#include "../pch.h"
#include "../include/OverlayBlacklist.h"
#include <algorithm>

namespace OblivionEye {
    static std::vector<std::wstring> g_titles = {
        L"cheat engine",
        L"x64dbg",
        L"process hacker",
        L"esp",
        L"overlay"
    };

    static std::vector<std::wstring> g_classes = {
        L"renderdocoverlay",
        L"discordoverlay",
        L"steamoverlay"
    };

    const std::vector<std::wstring>& GetBlacklistedWindowTitles() { return g_titles; }
    const std::vector<std::wstring>& GetBlacklistedWindowClasses() { return g_classes; }

    static std::wstring ToLower(const std::wstring& s) {
        std::wstring r = s;
        std::transform(r.begin(), r.end(), r.begin(), ::towlower);
        return r;
    }

    void AddBlacklistedWindowTitle(const std::wstring& titleSubstr) {
        auto low = ToLower(titleSubstr);
        if (std::find(g_titles.begin(), g_titles.end(), low) == g_titles.end())
            g_titles.push_back(low);
    }

    void AddBlacklistedWindowClass(const std::wstring& classSubstr) {
        auto low = ToLower(classSubstr);
        if (std::find(g_classes.begin(), g_classes.end(), low) == g_classes.end())
            g_classes.push_back(low);
    }
}
