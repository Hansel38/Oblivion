#include "../pch.h"
#include "../include/DriverScanner.h"
#include "../include/DriverBlacklist.h"
#include "../include/Utils.h"
#include "../include/Logger.h"
#include "../include/EventReporter.h"
#include <windows.h>
#include <psapi.h>
#include <vector>
#include <string>
#include <algorithm>
#include <thread>

#pragma comment(lib, "psapi.lib")

namespace OblivionEye {

    DriverScanner& DriverScanner::Instance() { static DriverScanner s; return s; }

    void DriverScanner::Start(unsigned intervalMs) {
        if (m_running.exchange(true)) return;
        std::thread([this, intervalMs]() { Loop(intervalMs); }).detach();
    }

    void DriverScanner::Stop() { m_running = false; }

    bool DriverScanner::IsBlacklistedLoaded() {
        // Enumerasi driver dari usermode via EnumDeviceDrivers
        LPVOID drivers[1024] = {};
        DWORD cbNeeded = 0;
        if (!EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded) || cbNeeded == 0)
            return false;
        int count = cbNeeded / sizeof(drivers[0]);
        wchar_t name[MAX_PATH];

        for (int i = 0; i < count; ++i) {
            if (GetDeviceDriverBaseNameW(drivers[i], name, MAX_PATH)) {
                std::wstring low = ToLower(name);
                for (const auto& bad : GetBlacklistedDriverNames()) {
                    if (low == ToLower(bad)) {
                        EventReporter::SendDetection(L"DriverScanner", name);
                        ShowDetectionAndExit(std::wstring(L"Driver: ") + name);
                        return true;
                    }
                }
            }
        }
        return false;
    }

    void DriverScanner::Loop(unsigned intervalMs) {
        Log(L"DriverScanner start");
        while (m_running) {
            if (IsBlacklistedLoaded()) {
                return; // ShowDetectionAndExit sudah menutup proses
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(intervalMs));
        }
        Log(L"DriverScanner stop");
    }
}
