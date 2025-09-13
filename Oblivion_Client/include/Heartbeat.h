#pragma once
#include "IDetector.h"

namespace OblivionEye {
    class Heartbeat : public IDetector {
    public:
        static Heartbeat& Instance();
        const wchar_t* Name() const override { return L"Heartbeat"; }
        unsigned IntervalMs() const override { return 10000; }
        void Tick() override; // single beat
        void Start(unsigned intervalMs = 10000) { (void)intervalMs; }
        void Stop() {}
        void TriggerNow();
        void EnableAdaptive(bool enable);
    private:
        Heartbeat() = default;
        unsigned m_idleStreak = 0;
        unsigned m_currentInterval = 10000;
        bool m_adaptive = false;
    };
}
