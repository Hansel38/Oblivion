#pragma once
#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include <string>

class ProcessWatcher {
public:
    // Tambahkan static di sini juga untuk konsistensi
    static bool IsBlacklistedProcessRunning();
};