#pragma once
#include <vector>
#include <string>

// Daftar proses yang diblacklist
const std::vector<std::wstring> BLACKLISTED_PROCESSES = {
    L"cheatengine.exe",
    L"cheatengine-x86_64.exe",
    L"cheatengine-x86.exe",
    L"cheatengine-i386.exe",
    L"openkore.exe",
    L"wpesniff.exe",
    L"rpesniff.exe",
    L"reclass.exe",
    L"reclass.net.exe",
    L"ida.exe",
    L"ida64.exe",
    L"x64dbg.exe",
    L"x32dbg.exe",
    L"ollydbg.exe",
    L"processhacker.exe",
    L"protection_id.exe",
    L"scylla.exe",
    L"scylla_x64.exe",
    L"scylla_x86.exe"
};