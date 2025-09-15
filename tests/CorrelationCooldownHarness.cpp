#include "../Oblivion_Client/include/DetectionCorrelator.h"
#include "../Oblivion_Client/include/Config.h"
#include <iostream>
#include <thread>

using namespace OblivionEye;

int main(){
    auto &c = DetectionCorrelator::Instance();
    c.Reset();
    // Simulate events that should trigger hook correlation
    c.Report(L"EAT", L"x", 2, true);
    c.Report(L"IAT", L"x", 2, true);
    c.Report(L"PROLOG", L"x", 1, true); // total weight >=5
    std::string first = c.GetStatusJson();
    // Immediately attempt same combo again (should be suppressed by cooldown & uniqueness)
    c.Report(L"EAT", L"x", 2, true);
    c.Report(L"IAT", L"x", 2, true);
    c.Report(L"PROLOG", L"x", 1, true);
    std::string second = c.GetStatusJson();
    std::cout << "First:  " << first << "\nSecond: " << second << "\n";
    std::cout << "(Expect hookDet unchanged)\n";
    // Sleep past cooldown then trigger again (optional short sleep for test brevity if constant large)
    std::this_thread::sleep_for(std::chrono::milliseconds( (Config::CORR_DETECTION_COOLDOWN_MS>1500)? 1600: Config::CORR_DETECTION_COOLDOWN_MS+100));
    c.Report(L"SYSCALL", L"y", 3, true); // new combo (SYSCALL included)
    std::string third = c.GetStatusJson();
    std::cout << "Third:  " << third << "\n";
    return 0;
}
