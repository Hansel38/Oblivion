#pragma once
#include <string>
#include <vector>

namespace OblivionEye {
    std::wstring ToLower(const std::wstring& s);
    std::wstring GetProcessImageName(DWORD pid);
    void ShowDetectionAndExit(const std::wstring& reason);
}
