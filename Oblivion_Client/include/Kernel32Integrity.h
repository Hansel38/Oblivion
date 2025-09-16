#pragma once
#include "IDetector.h"
#include <vector>
#include <array>

namespace OblivionEye {
    class Kernel32Integrity : public IDetector {
    public:
        static Kernel32Integrity& Instance();
        const wchar_t* Name() const override { return L"Kernel32Integrity"; }
        unsigned IntervalMs() const override { return 60000; }
        void Tick() override;
        void Start(unsigned intervalMs = 60000) { (void)intervalMs; }
        void Stop() {}
        // Wrapper publik untuk operasi rebaseline / verify tanpa membuka method internal asli
        bool RequestForceRebaseline() { return ForceRebaseline(); }
        bool RequestVerifyNow() { return VerifyNow(); }
    private:
        Kernel32Integrity() = default;
        bool Check();
        void CaptureBaseline();
        bool ForceRebaseline(); // manual rebaseline
        bool VerifyNow();       // on-demand verify
        bool CaptureSubsectionHashes();
        bool MapFreshDiskText(std::vector<unsigned long long>& diskChunks, unsigned long long& diskHash) const; // clean file copy

        // Persistence + HMAC (mirrors NtdllIntegrity design)
        void SaveBaseline();
        bool LoadBaseline();
        void ComputeHmac();
        bool VerifyHmac() const;
        void HmacSha256(const unsigned char* key, size_t keyLen, const unsigned char* data, size_t dataLen, unsigned char out[32]) const;
        void BuildKey(std::vector<unsigned char>& key) const; // obfuscated key (will later be centralized)
        std::vector<unsigned char> BuildHmacData() const;
        std::wstring HmacToHex() const;
        bool HexToHmac(const std::wstring& hex);

        bool m_baselineCaptured = false;
        unsigned long long m_baselineHash = 0ULL;
        std::vector<unsigned long long> m_chunkHashes;
        bool m_diskCaptured = false;
        unsigned long long m_diskHash = 0ULL;
        std::vector<unsigned long long> m_diskChunkHashes;
        std::array<unsigned char,32> m_hmac{}; bool m_hmacValid=false;
        std::array<unsigned char,32> m_prevChain{}; bool m_prevChainValid=false; // chain previous baseline HMAC
    };
}
