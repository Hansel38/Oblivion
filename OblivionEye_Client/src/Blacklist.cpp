#include "../include/Blacklist.h"

const std::vector<std::string> blacklistedProcesses = {
    "cheatengine-x86_64.exe",
    "cheatengine-i386.exe",
    "openkore.exe",
    "wpe.exe",
    "rpe.exe",
    "ollydbg.exe",
    "x64_dbg.exe",
    "x32_dbg.exe",
    "ida.exe",
    "ida64.exe",
    "processhacker.exe",
    "injector.exe",
    "dllinjector.exe"
    // JANGAN TAMBAHKAN chrome.exe atau browser lainnya
};