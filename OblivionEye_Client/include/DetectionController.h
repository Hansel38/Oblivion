#pragma once
#include <string>
#include <atomic>

namespace DetectionController {
    void Initialize();
    void RequestShutdown();              // manual shutdown (DLL unload)
    void ReportDetection(const std::string& reason); // central detection entry
    bool IsStopRequested();
    bool IsDetectionTriggered();
    std::string GetDetectionReason();
}
