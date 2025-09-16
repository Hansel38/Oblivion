#pragma once
#include "IDetector.h"
#include <cstdint>
#include <array>

namespace OblivionEye {
    // Placeholder: Collect lightweight userland snapshots (PEB fields, loaded module count) and compare vs optional future kernel driver feed.
    class KernelSurfaceStub : public IDetector {
    public:
        static KernelSurfaceStub& Instance();
        const wchar_t* Name() const override { return L"KernelSurfaceStub"; }
        unsigned IntervalMs() const override { return 60000; }
        void Tick() override;
        void Start(unsigned intervalMs = 60000) { (void)intervalMs; }
        void Stop() {}
    private:
        KernelSurfaceStub() = default;
        bool m_baselineCaptured=false;
        uint64_t m_pebHash=0; // truncated SHA256 of selected fields
        uint32_t m_modCount=0;
        void CaptureBaseline();
        bool Check();
    };
}
