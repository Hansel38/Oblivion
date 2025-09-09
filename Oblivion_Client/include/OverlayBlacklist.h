#pragma once
#include <vector>
#include <string>

namespace OblivionEye {
    // Daftar judul window atau kelas yang mencurigakan (lowercase). Substring match.
    const std::vector<std::wstring>& GetBlacklistedWindowTitles();
    const std::vector<std::wstring>& GetBlacklistedWindowClasses();

    // Tambahkan item baru secara dinamis (akan disimpan dalam lowercase)
    void AddBlacklistedWindowTitle(const std::wstring& titleSubstr);
    void AddBlacklistedWindowClass(const std::wstring& classSubstr);

    // Bersihkan daftar blacklist
    void ClearOverlayTitleBlacklist();
    void ClearOverlayClassBlacklist();
}
