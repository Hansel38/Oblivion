#include "../pch.h"
#include "../include/AntiTestMode.h"
#include "../include/Utils.h"
#include "../include/Logger.h"
#include "../include/EventReporter.h"
#include <windows.h>
#include <thread>
#include <chrono>

namespace OblivionEye {

    AntiTestMode& AntiTestMode::Instance() { static AntiTestMode s; return s; }

    static bool CheckBCDTestSigning() {
        // Query status testsigning via api bcdedit sulit di usermode, gunakan registry policy sebagai indikator tambahan.
        // Heuristik ringan: cek sistem environment variable TESTSIGNING (kadang tidak tersedia). Jika tidak ada, fallback ke GetSystemMetrics(SM_SERVERR2) bukan pengganti, jadi kita abaikan.
        // Untuk basic, gunakan panggilan undocumented RtlGetNtVersionNumbers tidak diperlukan. Kita gunakan NtQuerySystemInformation? Terlalu berat.
        // Simpelnya: gunakan dua indikator: (1) registry CodeIntegrity > TestFlags, (2) adanya watermark.
        HKEY hKey;
        DWORD val = 0, size = sizeof(val);
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\CI", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            if (RegQueryValueExW(hKey, L"TestFlags", nullptr, nullptr, reinterpret_cast<LPBYTE>(&val), &size) == ERROR_SUCCESS) {
                RegCloseKey(hKey);
                if (val != 0) return true;
            } else {
                RegCloseKey(hKey);
            }
        }
        return false;
    }

    bool AntiTestMode::IsTestModeEnabled() {
        return CheckBCDTestSigning();
    }

    void AntiTestMode::Start(unsigned intervalMs) {
        if (m_running.exchange(true)) return;
        std::thread([this, intervalMs]() { Loop(intervalMs); }).detach();
    }

    void AntiTestMode::Stop() { m_running = false; }

    void AntiTestMode::Loop(unsigned intervalMs) {
        Log(L"AntiTestMode start");
        while (m_running) {
            if (IsTestModeEnabled()) {
                EventReporter::SendDetection(L"AntiTestMode", L"/testsigning");
                ShowDetectionAndExit(L"Windows Test Mode terdeteksi");
                return;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(intervalMs));
        }
        Log(L"AntiTestMode stop");
    }
}
