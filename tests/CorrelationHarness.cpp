#include "../Oblivion_Client/include/DetectionCorrelator.h"
#include <iostream>
#include <thread>

// Minimal stub constants if not linked against full config (adjust if already defined in project build)
namespace OblivionEye { namespace Config {
    const unsigned CORR_WINDOW_MS = 5000; // 5s window for test
    const unsigned CORR_PRUNE_INTERVAL_MS = 200; 
    const unsigned CORR_SCORE_THRESHOLD = 5; 
    const unsigned CORR_TRIGGER_DISTINCT = 3; 
} }

using OblivionEye::DetectionCorrelator;

static void FeedHooks() {
    auto &c = DetectionCorrelator::Instance();
    c.Report(L"EAT", L"eat1", 2, true);
    c.Report(L"IAT", L"iat1", 2, true);
    c.Report(L"PROLOG", L"pro1", 2, true); // should push score >= threshold
}

static void FeedMultiSourcePartial() {
    auto &c = DetectionCorrelator::Instance();
    c.Report(L"CE_PARTIAL", L"ce1", 1, true);
    c.Report(L"SIG_PARTIAL", L"sig1", 1, true);
    c.Report(L"EXT_HANDLE", L"h1", 1, true); // three distinct low-weight categories
}

int main() {
    std::wcout << L"Initial: " << DetectionCorrelator::Instance().GetStatus() << L"\n";

    FeedHooks();
    std::wcout << L"After Hooks: " << DetectionCorrelator::Instance().GetStatus() << L"\n";

    FeedMultiSourcePartial();
    std::wcout << L"After MultiSource Partial: " << DetectionCorrelator::Instance().GetStatus() << L"\n";

    std::cout << "JSON: " << DetectionCorrelator::Instance().GetStatusJson() << "\n";
    return 0;
}
