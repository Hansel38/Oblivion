#pragma once
#include <string>
#include <vector>
#include <unordered_set>
#include <unordered_map>
#include <mutex>
#include <sstream>
#include <windows.h>
// Implementasi penuh di cpp; tidak perlu forward declare konstanta Config (hindari redefinition dengan constexpr)

namespace OblivionEye {
    class DetectionCorrelator {
    public:
        struct Entry { std::wstring cat; std::wstring detail; unsigned long long tick; int weight; };
        static DetectionCorrelator& Instance();
        void Report(const std::wstring& category, const std::wstring& detail, int weight=1, bool highPriority=false);
    void Reset(); // Flush semua state & metrics
    std::wstring GetStatus();
    std::string GetStatusJson(); // new lightweight JSON-like status
    private:
        DetectionCorrelator() = default;
        void Prune(unsigned long long now);
        void Evaluate(unsigned long long now);
        static unsigned long long NowMs() { return ::GetTickCount64(); }
        std::vector<Entry> m_entries;
    std::unordered_set<std::wstring> m_sentCombos; // Kombinasi sudah pernah dikirim (untuk uniqueness dalam window)
    // Metrics
    unsigned long long m_metricsEvaluations = 0;
    unsigned long long m_metricsPrunes = 0;
    unsigned long long m_metricsHookDetections = 0;
    unsigned long long m_metricsMultiDetections = 0;
    unsigned long long m_lastHookDetectTick = 0;
    unsigned long long m_lastMultiDetectTick = 0;
        unsigned long long m_lastStatusSnapshot = 0;
        unsigned long long m_lastPruneTick = 0;
        std::mutex m_mtx;
    };
}
