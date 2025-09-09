#pragma once
#include <atomic>
#include <cstdint>
#include <string>
#include <mutex>

namespace OblivionEye {
    struct StatsSnapshot {
        uint64_t detections = 0;
        uint64_t infoEvents = 0;
        uint64_t heartbeats = 0;
        uint64_t lastUptimeSec = 0;
    };

    class RuntimeStats {
    public:
        static RuntimeStats& Instance();
        void IncDetection();
        void IncInfo();
        void IncHeartbeat();
        StatsSnapshot GetSnapshot();
        void SetStartTick();
    private:
        RuntimeStats() = default;
        std::atomic<uint64_t> m_detections{0};
        std::atomic<uint64_t> m_info{0};
        std::atomic<uint64_t> m_heartbeats{0};
        uint64_t m_startTick = 0; // GetTickCount64 baseline
        std::mutex m_mtx; // protect startTick
    };
}
