#pragma once
#include <string>
#include <atomic>
#include <chrono>
#include "Config.h" // diperlukan untuk konstanta INTEGRITY_EXPORT_* (namespace OblivionEye::Config)

namespace OblivionEye {
    class IntegrityExport {
    public:
        static IntegrityExport& Instance();
        // Called periodically (e.g. from main loop) to decide if push is due
        void Tick();
        // Force immediate send regardless of interval (if enabled)
        void SendNow();
        // Runtime controls
        void SetEnabled(bool en);
        void SetIntervalMs(unsigned ms);
        bool IsEnabled() const { return m_enabled.load(); }
        unsigned IntervalMs() const { return m_intervalMs.load(); }
        // Runtime HMAC flags
        void SetHmacEnabled(bool v){ m_hmacEnabled.store(v); }
        void SetHmacRequire(bool v){ m_hmacRequire.store(v); }
        bool IsHmacEnabled() const { return m_hmacEnabled.load(); }
        bool IsHmacRequire() const { return m_hmacRequire.load(); }
    private:
        IntegrityExport();
        std::wstring BuildJsonSnapshot() const; // JSON object (modules as keys)
        void DoSend(const std::wstring& json);
        std::wstring StatusString() const { return (m_enabled.load()?L"ENABLED":L"DISABLED") + std::wstring(L" interval=") + std::to_wstring(m_intervalMs.load()); }
        std::atomic<bool> m_enabled{ false };
        std::atomic<unsigned> m_intervalMs{ 0 };
        std::chrono::steady_clock::time_point m_lastSend;
    std::atomic<bool> m_hmacEnabled{ OblivionEye::Config::INTEGRITY_EXPORT_HMAC_ENABLED_DEFAULT };
    std::atomic<bool> m_hmacRequire{ OblivionEye::Config::INTEGRITY_EXPORT_HMAC_REQUIRE_DEFAULT };
        // Session id (128-bit random hex) & sequence number
        std::wstring m_sessionId; // wide for concatenation; send as utf8
        std::atomic<unsigned long long> m_seq{0};
        void EnsureSession();
    };
}
