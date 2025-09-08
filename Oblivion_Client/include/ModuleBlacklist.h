#pragma once
#include <vector>
#include <string>

namespace OblivionEye {
    // Daftar nama modul/DLL yang diblacklist (lowercase, filename saja)
    const std::vector<std::wstring>& GetBlacklistedModuleNames();
    // Tambah nama modul ke blacklist (lowercase, unik)
    void AddBlacklistedModuleName(const std::wstring& name);
}
