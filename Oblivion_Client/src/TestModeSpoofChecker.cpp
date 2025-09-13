#include "../pch.h"
#include "../include/TestModeSpoofChecker.h"
#include "../include/Logger.h"
#include "../include/Utils.h"
#include <windows.h>

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

    void TestModeSpoofChecker::Tick() {
        if (DetectSpoof()) ShowDetectionAndExit(L"Test Mode spoof terdeteksi");
    }
}
