#pragma once
// Central log tag definitions to avoid repeated string literals.
// Use wide literals for existing logging interface expecting std::wstring.

namespace OblivionEye::LogTags {
    inline constexpr wchar_t INFO[]       = L"INFO";
    inline constexpr wchar_t DETECTION[]  = L"DETECTION";
    inline constexpr wchar_t RESULT[]     = L"RESULT";
    inline constexpr wchar_t STATUS[]     = L"STATUS";
    inline constexpr wchar_t INTERVALS[]  = L"INTERVALS";
    inline constexpr wchar_t SELFTEST[]   = L"SELFTEST";
    inline constexpr wchar_t PROLOG[]     = L"PROLOG";
    inline constexpr wchar_t CONFIG[]     = L"CONFIG";
}
