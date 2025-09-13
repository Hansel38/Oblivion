#pragma once
#include "IDetector.h"
#include <atomic>

namespace OblivionEye {
    class ProcessWatcher : public IDetector {
    public:
        static ProcessWatcher& Instance();
        const wchar_t* Name() const override { return L"ProcessWatcher"; }
        unsigned IntervalMs() const override { return 1000; } // internal WMI/poll handles timing
        void Tick() override; // lightweight noop after initial start (WMI events handled separately)
        void Start(); // legacy start to bootstrap WMI thread then converts to passive
        void Stop();
    private:
        ProcessWatcher() = default;
        void InitialScan();
        void WatchNewProcesses();
        std::atomic<bool> m_running{ false };
        bool m_initialized = false;
    };
}
