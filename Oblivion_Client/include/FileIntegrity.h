#pragma once
#include <string>

namespace OblivionEye {
    // MD5 sederhana menggunakan WinCrypt
    std::wstring MD5OfFile(const std::wstring& path);
}
