#include "../pch.h"
#include "../include/AntiTestMode.h"
#include "../include/Utils.h"
#include "../include/Logger.h"
#include "../include/EventReporter.h"
#include <windows.h>

namespace OblivionEye {
namespace {
    bool CheckBCDTestSigning() {
        HKEY hKey = nullptr;
        DWORD val = 0, size = sizeof(val);
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\CI", 0, KEY_READ, &hKey) != ERROR_SUCCESS)
            return false;

        LSTATUS st = RegQueryValueExW(hKey, L"TestFlags", nullptr, nullptr, reinterpret_cast<LPBYTE>(&val), &size);
        RegCloseKey(hKey);
        if (st == ERROR_SUCCESS && val != 0)
            return true;
        return false;
    }
}

AntiTestMode &AntiTestMode::Instance() { static AntiTestMode s; return s; }

bool AntiTestMode::IsTestModeEnabled() { return CheckBCDTestSigning(); }

void AntiTestMode::Tick() {
    if (IsTestModeEnabled()) {
        EventReporter::SendDetection(L"AntiTestMode", L"/testsigning");
        ShowDetectionAndExit(L"Windows Test Mode terdeteksi");
    }
}
}
