#pragma once
#include "IDetector.h"
#include <vector>

namespace OblivionEye {
    class MemoryHeuristics : public IDetector {
    public:
        static MemoryHeuristics& Instance();
        const wchar_t* Name() const override { return L"MemoryHeuristics"; }
        unsigned IntervalMs() const override { return 45000; }
        void Tick() override;
        void Start(unsigned intervalMs = 45000) { (void)intervalMs; }
        void Stop() {}
    private:
        MemoryHeuristics() = default;
        bool Scan();
        double Entropy(const unsigned char* data, size_t len);
    };
}
