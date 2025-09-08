#pragma once
#include <vector>
#include <string>

namespace OblivionEye {
    // Daftar nama driver yang diblacklist (lowercase, base name saja, contoh: dbk32.sys)
    const std::vector<std::wstring>& GetBlacklistedDriverNames();
    // Tambahkan nama driver ke blacklist (lowercase, unik)
    void AddBlacklistedDriverName(const std::wstring& name);
}
