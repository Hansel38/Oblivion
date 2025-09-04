#pragma once
#include <chrono>
#include <thread>
#include "DetectionController.h"

inline void SleepWithStopSeconds(int seconds) {
    const int sliceMs = 100;
    int totalSlices = seconds * 1000 / sliceMs;
    for (int i = 0; i < totalSlices; ++i) {
        if (DetectionController::IsStopRequested()) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(sliceMs));
    }
}

inline void SleepWithStopMilliseconds(int ms) {
    const int sliceMs = 50;
    int totalSlices = ms / sliceMs;
    for (int i = 0; i < totalSlices; ++i) {
        if (DetectionController::IsStopRequested()) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(sliceMs));
    }
}
