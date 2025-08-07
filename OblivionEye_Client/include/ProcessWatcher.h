#pragma once
#include <string>
#include <vector>
#include <algorithm>    // Untuk std::transform
#include <cctype>       // Untuk ::tolower
#include <windows.h>    // Tambahkan ini juga

// Deklarasi fungsi toLower inline untuk menghindari duplikat
inline std::string toLower(const std::string& data) {
    std::string result = data;
    std::transform(result.begin(), result.end(), result.begin(), ::tolower);
    return result;
}

// Deklarasi fungsi ws2s inline untuk menghindari duplikat
inline std::string ws2s(const std::wstring& wstr) {
    if (wstr.empty()) return std::string();
    int size_needed = WideCharToMultiByte(CP_ACP, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_ACP, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}

// Deklarasi fungsi
bool ScanRunningProcesses();
void ContinuousProcessScan();