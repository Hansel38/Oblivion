#pragma once
#include "IDetector.h"
#include <vector>
#include <array>

namespace OblivionEye {
    class NtdllIntegrity : public IDetector {
    public:
        static NtdllIntegrity& Instance();
        const wchar_t* Name() const override { return L"NtdllIntegrity"; }
        unsigned IntervalMs() const override { return 60000; }
        void Tick() override; // perform integrity check
        void Start(unsigned intervalMs = 60000) { (void)intervalMs; }
        void Stop() {}
        // Wrapper publik (aman) untuk operasi maintenance yang sebelumnya private
        bool RequestForceRebaseline() { return ForceRebaseline(); }
        bool RequestVerifyNow() { return VerifyNow(); }
    private:
        NtdllIntegrity() = default;
        bool Check();
        void CaptureBaseline();
        bool ForceRebaseline(); // manual rebaseline with telemetry
        bool VerifyNow();       // on-demand verify without termination
        bool CaptureSubsectionHashes();
        void SaveBaseline();
        bool LoadBaseline();
        void ComputeHmac();
        bool VerifyHmac() const;
        bool MapFreshDiskText(std::vector<unsigned long long>& diskChunks, unsigned long long& diskHash) const; // compare with clean file copy
    // HMAC helper (uses centralized HashUtil SHA-256)
    void HmacSha256(const unsigned char* key, size_t keyLen, const unsigned char* data, size_t dataLen, unsigned char out[32]) const;
        void BuildKey(std::vector<unsigned char>& key) const; // obfuscated key builder
        std::vector<unsigned char> BuildHmacData() const;
        std::wstring HmacToHex() const;
        bool HexToHmac(const std::wstring& hex);
        bool m_baselineCaptured = false;
        unsigned long long m_baselineHash = 0ULL; // runtime hash (truncated SHA256) for ntdll .text
        std::vector<unsigned long long> m_chunkHashes; // runtime chunk hashes
        // Disk (clean file) reference
        bool m_diskCaptured = false;
        unsigned long long m_diskHash = 0ULL;
        std::vector<unsigned long long> m_diskChunkHashes;
        // HMAC of serialized baseline
        std::array<unsigned char,32> m_hmac{};
        bool m_hmacValid = false;
        // Previous chain HMAC (for version >=2)
        std::array<unsigned char,32> m_prevChain{}; bool m_prevChainValid=false;
    };
}
