#pragma once
// StringUtil.h - UTF-8 / wide string conversion helpers (header-only)
// Centralizes conversions to avoid repetitive boilerplate & potential narrowing warnings.
// All functions return empty string on failure.

#include <string>
#include <windows.h>

namespace OblivionEye::StringUtil {

inline std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) return std::wstring();
    int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    if (len <= 0) return std::wstring();
    std::wstring w(static_cast<size_t>(len), L'\0');
    if (!MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &w[0], len)) return std::wstring();
    if (!w.empty() && w.back() == L'\0') w.pop_back();
    return w;
}

inline std::string WideToUtf8(const std::wstring& w) {
    if (w.empty()) return std::string();
    int len = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (len <= 0) return std::string();
    std::string s(static_cast<size_t>(len), '\0');
    if (!WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, &s[0], len, nullptr, nullptr)) return std::string();
    if (!s.empty() && s.back() == '\0') s.pop_back();
    return s;
}

inline std::string WideAsciiLossy(const std::wstring& w) {
    // Fast lossy ASCII fallback (non-ASCII -> '?')
    std::string out; out.reserve(w.size());
    for (wchar_t c : w) out.push_back((c >= 32 && c < 127) ? static_cast<char>(c) : '?');
    return out;
}

} // namespace OblivionEye::StringUtil
