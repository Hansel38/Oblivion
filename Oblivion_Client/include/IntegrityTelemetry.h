#pragma once
#include <string>
#include <unordered_map>
#include <cstdint>
#include <mutex>
#include <chrono>

namespace OblivionEye {

    struct IntegrityModuleStats {
        uint32_t baselineLoadsOk = 0;
        uint32_t baselineLoadsFail = 0;
        uint32_t hmacMismatch = 0;
        uint32_t rebaselineCount = 0;          // automatic (auto-whitelist triggered) + manual
        uint32_t manualRebaselineCount = 0;     // subset of rebaselineCount
        uint32_t chainAdvanceCount = 0;         // times previous HMAC chained forward
        uint32_t autoWhitelistCount = 0;        // aw counter (mirrors RuntimeStats but per-module persistent snapshot)
        uint32_t verifyNowRequests = 0;         // count of INTEGRITY_VERIFY triggers
        uint32_t forceVerifyFailures = 0;       // verify-now found mismatch (should normally escalate)
        uint32_t totalChunks = 0;               // last known chunk count baseline
        uint32_t whitelistedChunks = 0;         // snapshot of whitelisted chunk count
        std::wstring lastAutoWhitelistTime;     // ISO8601-like
        std::wstring lastBaselineTime;          // capture time last baseline save
        std::wstring lastManualRebaselineTime;
        bool hmacValid = false;                 // current baseline HMAC validity
        uint32_t chainDepth = 0;                // number of links (previous chain captures)
    };

    class IntegrityTelemetry {
    public:
        static IntegrityTelemetry& Instance();
        IntegrityModuleStats Get(const std::wstring& module);
        void Update(const std::wstring& module, const IntegrityModuleStats& stats);
        IntegrityModuleStats& Ref(const std::wstring& module); // direct reference (use carefully with lock)
        std::wstring NowIsoPublic() const { return NowIso(); }
    private:
        IntegrityTelemetry() = default;
        std::unordered_map<std::wstring, IntegrityModuleStats> m_stats;
        std::mutex m_mtx;
        std::wstring NowIso() const; // helper
    };
}
