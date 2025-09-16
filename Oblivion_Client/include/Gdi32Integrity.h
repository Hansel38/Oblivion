#pragma once
#include "IDetector.h"
#include <vector>
#include <array>

namespace OblivionEye {
    class Gdi32Integrity : public IDetector {
    public:
        static Gdi32Integrity& Instance();
        const wchar_t* Name() const override { return L"Gdi32Integrity"; }
        unsigned IntervalMs() const override { return 90000; }
        void Tick() override;
        void Start(unsigned intervalMs = 90000) { (void)intervalMs; }
        void Stop() {}
        bool RequestForceRebaseline() { return ForceRebaseline(); }
        bool RequestVerifyNow() { return VerifyNow(); }
    private:
        Gdi32Integrity() = default;
        bool Check();
        void CaptureBaseline();
        bool ForceRebaseline();
        bool VerifyNow();
        bool CaptureSubsectionHashes();
        bool MapFreshDiskText(std::vector<unsigned long long>& diskChunks, unsigned long long& diskHash) const;
        void SaveBaseline(); bool LoadBaseline(); void ComputeHmac(); bool VerifyHmac() const;
        void HmacSha256(const unsigned char* key,size_t keyLen,const unsigned char* data,size_t dataLen,unsigned char out[32]) const;
        void BuildKey(std::vector<unsigned char>& key) const; std::vector<unsigned char> BuildHmacData() const;
        std::wstring HmacToHex() const; bool HexToHmac(const std::wstring& hex);
        bool m_baselineCaptured=false; unsigned long long m_baselineHash=0ULL; std::vector<unsigned long long> m_chunkHashes;
        bool m_diskCaptured=false; unsigned long long m_diskHash=0ULL; std::vector<unsigned long long> m_diskChunkHashes;
        std::array<unsigned char,32> m_hmac{}; bool m_hmacValid=false; std::array<unsigned char,32> m_prevChain{}; bool m_prevChainValid=false;
    };
}
