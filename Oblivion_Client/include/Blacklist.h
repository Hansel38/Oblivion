#pragma once
#include <vector>
#include <string>

namespace OblivionEye {
    // Mengembalikan daftar nama process (lowercase) yang diblacklist
    const std::vector<std::wstring>& GetBlacklistedProcessNames();
    // Tambah nama proses ke blacklist (akan disimpan dalam lowercase)
    void AddBlacklistedProcessName(const std::wstring& name);
}
