#pragma once
#include <atomic>

namespace OblivionEye {
    class TestModeSpoofChecker {
    public:
        static TestModeSpoofChecker& Instance();
        void Start(unsigned intervalMs = 30000);
        void Stop();
    private:
        TestModeSpoofChecker() = default;
        void Loop(unsigned intervalMs);
        bool DetectSpoof();
        std::atomic<bool> m_running{ false };
    };
}
