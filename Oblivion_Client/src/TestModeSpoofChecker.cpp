#include "../pch.h"
#include "../include/TestModeSpoofChecker.h"
#include "../include/Logger.h"
#include "../include/Utils.h"
#include <windows.h>

namespace OblivionEye {
namespace {
    bool CheckSuspiciousRegKeys() {
        // Placeholder heuristic; currently disabled to avoid false positives.
        return false;
    }
}

TestModeSpoofChecker &TestModeSpoofChecker::Instance() { static TestModeSpoofChecker s; return s; }

bool TestModeSpoofChecker::DetectSpoof() { return CheckSuspiciousRegKeys(); }

void TestModeSpoofChecker::Tick() { if (DetectSpoof()) ShowDetectionAndExit(L"Test Mode spoof terdeteksi"); }
}
