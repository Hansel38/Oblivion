#include "../Oblivion_Client/include/DetectionCorrelator.h"
#include "../Oblivion_Client/include/Config.h"
#include <thread>
#include <vector>
#include <atomic>
#include <random>
#include <iostream>
#include <chrono>

using namespace OblivionEye;

// Simple concurrency stress: spawn N threads, each pushes random categories for D ms.
int main(){
    constexpr int THREADS = 8;
    constexpr int DURATION_MS = 1200; // short run
    std::vector<std::thread> th;
    std::atomic<bool> startFlag{false};
    std::atomic<int> ready{0};

    const std::wstring cats[] = {L"EAT",L"IAT",L"PROLOG",L"SYSCALL",L"CE_PARTIAL",L"SIG_PARTIAL",L"EXT_HANDLE"};
    std::mt19937 rng{std::random_device{}()};

    for(int i=0;i<THREADS;++i){
        th.emplace_back([&]{
            ++ready; while(!startFlag.load()) std::this_thread::yield();
            auto start = GetTickCount64();
            std::mt19937 lrng{(unsigned)std::hash<std::thread::id>{}(std::this_thread::get_id())};
            std::uniform_int_distribution<int> catDist(0,(int)(std::size(cats)-1));
            std::uniform_int_distribution<int> weightDist(1,3);
            while(GetTickCount64() - start < (unsigned long long)DURATION_MS){
                int idx = catDist(lrng);
                int w = weightDist(lrng);
                DetectionCorrelator::Instance().Report(cats[idx], L"concurrent", w, false);
                if((GetTickCount64() & 0xFF)==0) {
                    // occasional high priority
                    DetectionCorrelator::Instance().Report(cats[idx], L"burst", w+1, true);
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
        });
    }
    while(ready.load() < THREADS) std::this_thread::yield();
    startFlag = true;

    for(auto &t: th) t.join();

    std::wcout << L"Final status: " << DetectionCorrelator::Instance().GetStatus() << std::endl;
    std::cout  << "JSON: " << DetectionCorrelator::Instance().GetStatusJson() << std::endl;
    return 0;
}
