#pragma once
#include <string>

namespace OblivionEye {
    class PolicyManager {
    public:
        static bool LoadPolicy(const std::wstring& path); // return true jika sukses
        static bool SavePolicy(const std::wstring& path); // simpan konfigurasi runtime
    };
}
