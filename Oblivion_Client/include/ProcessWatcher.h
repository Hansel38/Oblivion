#pragma once
#include <atomic>

namespace OblivionEye {
    class ProcessWatcher {
    public:
        static ProcessWatcher& Instance();
        void Start();
        void Stop();
    private:
        ProcessWatcher() = default;
        void InitialScan();
        void WatchNewProcesses();
        std::atomic<bool> m_running{ false };
    };
}
