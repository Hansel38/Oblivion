#pragma once
#include "IDetector.h"
#include <vector>
#include <string>
#include <mutex>

namespace OblivionEye {
    struct PrologTarget { std::wstring module; std::string function; size_t minBytes; };
    class PrologHookChecker : public IDetector {
    public:
        static PrologHookChecker& Instance();
        const wchar_t* Name() const override { return L"PrologHookChecker"; }
        unsigned IntervalMs() const override { return 45000; }
        void Tick() override;
        void Start(unsigned intervalMs = 45000) { (void)intervalMs; }
        void Stop() {}
        void AddTarget(const std::wstring& moduleName, const std::string& funcName, size_t minBytes = 8);
        void Rebaseline();
        std::vector<PrologTarget> GetTargets();
    private:
        PrologHookChecker() = default;
        bool Scan();
        bool CheckFunction(size_t index);
        void CaptureBaselines(bool forceAll = false);
        bool m_baselineCaptured = false;
        std::vector<PrologTarget> m_targets;
        std::vector<std::vector<unsigned char>> m_baselines;
        std::mutex m_mtx;
    };
}
