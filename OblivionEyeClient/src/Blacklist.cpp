#include "../include/Blacklist.h"

const std::vector<std::string> BLACKLISTED_PROCESSES = {
    "cheatengine",
    "cheatenginex86_64",
    "openkore",
    "wpe",
    "rpe",
    "ollydbg",
    "x64dbg",
    "x32dbg"
};

const std::vector<std::string> OVERLAY_BLACKLIST = {
    "cheat engine",
    "game trainer",
    "memory editor",
    "debugger",
    "esp hack",
    "wallhack",
    "aimbot",
    "speed hack",
    "damage hack",
    "injected dll",
    "hack tool"
};

// Tambahkan whitelist
const std::vector<std::string> WHITELISTED_WINDOWS = {
    "notepad",
    "calculator",
    "task manager",
    "visual studio",
    "code",
    "sublime",
    "chrome",
    "firefox",
    "edge",
    "explorer",
    "mencari signature"
};

// Pastikan DLL_BLACKLIST didefinisikan
const std::vector<std::string> DLL_BLACKLIST = {
    "cheatengine",
    "speedhack",
    "kernelhook",
    "injector",
    "trainer",
    "hack",
    "memoryeditor",
    "debugger"
};