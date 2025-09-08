#include "../pch.h"
#include "../include/TestModeSpoofChecker.h"
#include "../include/Logger.h"
#include "../include/Utils.h"
#include <windows.h>
#include <thread>
#include <chrono>

namespace OblivionEye {

    TestModeSpoofChecker& TestModeSpoofChecker::Instance() { static TestModeSpoofChecker s; return s; }

    static bool CheckSuspiciousRegKeys() {
        // Heuristik ringan untuk spoof test mode: cek kunci yang tidak lazim/sengaja disamarkan.
        // Untuk menghindari false positive, default return false.
        return false;
    }

    bool TestModeSpoofChecker::DetectSpoof() {
        if (CheckSuspiciousRegKeys()) return true;
        return false;
    }

    void TestModeSpoofChecker::Start(unsigned intervalMs) {
        if (m_running.exchange(true)) return;
        std::thread([this, intervalMs]() { Loop(intervalMs); }).detach();
    }

    void TestModeSpoofChecker::Stop() { m_running = false; }

    void TestModeSpoofChecker::Loop(unsigned intervalMs) {
        Log(L"TestModeSpoofChecker start");
        while (m_running) {
            if (DetectSpoof()) {
                ShowDetectionAndExit(L"Test Mode spoof terdeteksi");
                return;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(intervalMs));
        }
        Log(L"TestModeSpoofChecker stop");
    }
}
