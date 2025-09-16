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
        uint64_t awNtdll = 0;
        uint64_t awKernel32 = 0;
        uint64_t awUser32 = 0;
        uint64_t awGdi32 = 0;
    };

    class RuntimeStats {
    public:
        static RuntimeStats& Instance();
        void IncDetection();
        void IncInfo();
        void IncHeartbeat();
        void IncAwNtdll();
        void IncAwKernel32();
        void IncAwUser32();
        void IncAwGdi32();
        StatsSnapshot GetSnapshot();
        void SetStartTick();
    private:
        RuntimeStats() = default;
        std::atomic<uint64_t> m_detections{0};
        std::atomic<uint64_t> m_info{0};
        std::atomic<uint64_t> m_heartbeats{0};
        std::atomic<uint64_t> m_awNtdll{0};
        std::atomic<uint64_t> m_awKernel32{0};
        std::atomic<uint64_t> m_awUser32{0};
        std::atomic<uint64_t> m_awGdi32{0};
        uint64_t m_startTick = 0; // GetTickCount64 baseline
        std::mutex m_mtx; // protect startTick
    };
}
