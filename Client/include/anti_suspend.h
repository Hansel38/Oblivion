#pragma once

namespace AntiSuspend {
    void InitializeThreadMonitoring();
    bool IsThreadSuspended();
    void StopThreadMonitoring();
}