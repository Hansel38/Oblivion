#pragma once
#include <string>
#include <vector>
#include <unordered_set>
#include <mutex>

namespace OblivionEye {
    class DetectionCorrelator {
    public:
        struct Entry { std::wstring cat; std::wstring detail; unsigned long long tick; }; // made public for helper usage
        static DetectionCorrelator& Instance();
        void Report(const std::wstring& category, const std::wstring& detail);
    private:
        DetectionCorrelator() = default;
        std::vector<Entry> m_entries;
        std::unordered_set<std::wstring> m_sentCombos;
        unsigned long long m_lastPruneTick = 0;
        std::mutex m_mtx;
        void Prune(unsigned long long now);
    };
}
