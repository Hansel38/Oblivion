#include <iostream>
#include <vector>
#include <chrono>
#include <thread>

// Include core detectors & scheduler
#include "../Oblivion_Client/include/Kernel32Integrity.h"
#include "../Oblivion_Client/include/NtdllIntegrity.h"
#include "../Oblivion_Client/include/User32Integrity.h"
#include "../Oblivion_Client/include/Gdi32Integrity.h"
#include "../Oblivion_Client/include/DetectorScheduler.h"
#include "../Oblivion_Client/include/EventReporter.h"
#include "../Oblivion_Client/include/Logger.h"

// Minimal stub Logger / EventReporter backends could be provided if they require pipe, but
// here we rely on them being no-ops if pipe not connected.

using namespace OblivionEye;

static void RunIntegrityBaselineAndCheck() {
    auto &k = Kernel32Integrity::Instance();
    auto &n = NtdllIntegrity::Instance();
    auto &u = User32Integrity::Instance();
    auto &g = Gdi32Integrity::Instance();

    // First Tick() captures baseline
    k.Tick(); n.Tick(); u.Tick(); g.Tick();
    std::wcout << L"Baseline captured for integrity detectors" << std::endl;

    // Simulate wait and re-run (should early exit unless modified)
    k.Tick(); n.Tick(); u.Tick(); g.Tick();
    std::wcout << L"Second pass (no modifications expected) completed" << std::endl;
}

static void RunSchedulerSelfTest() {
    auto &sched = DetectorScheduler::Instance();
    // Add a subset of detectors (integrity ones) to scheduler
    sched.Add(&Kernel32Integrity::Instance());
    sched.Add(&NtdllIntegrity::Instance());
    sched.Add(&User32Integrity::Instance());
    sched.Add(&Gdi32Integrity::Instance());

    auto results = sched.RunSelfTest();
    std::wcout << L"SelfTest results (name:ms):" << std::endl;
    for (auto &r : results) {
        std::wcout << L"  " << r.name << L":" << r.durationMs << std::endl;
    }
}

int main() {
    try {
        RunIntegrityBaselineAndCheck();
        RunSchedulerSelfTest();
        std::wcout << L"Harness completed." << std::endl;
    } catch (const std::exception &ex) {
        std::cerr << "Exception: " << ex.what() << std::endl;
        return 1;
    }
    return 0;
}
