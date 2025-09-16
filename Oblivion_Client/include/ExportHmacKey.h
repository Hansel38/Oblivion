#pragma once
#include <string>
#include <mutex>

namespace OblivionEye {
    class ExportHmacKey {
    public:
        static ExportHmacKey& Instance();
        void SetFromUtf8(const std::string& k);
        std::string GetUtf8() const; // returns copy
        // Rotasi otomatis/manual
        bool RotateRandom(); // generate key random 32 bytes -> hex 64 chars
        void SetRotationIntervalMs(unsigned ms){ m_rotationIntervalMs.store(ms); }
        unsigned GetRotationIntervalMs() const { return m_rotationIntervalMs.load(); }
        void Tick(); // panggil periodik (misal reuse scheduler atau bagian dari IntegrityExport Tick future)
        std::wstring GetLastRotationTime() const; // ISO8601 singkat
    private:
        ExportHmacKey();
        mutable std::mutex m_mtx;
        std::string m_keyUtf8; // stored plain in memory (obfuscate later if needed)
        std::atomic<unsigned> m_rotationIntervalMs{0};
        std::chrono::steady_clock::time_point m_lastRotation; // steady for interval
        std::wstring m_lastRotationIso;
    };
}
