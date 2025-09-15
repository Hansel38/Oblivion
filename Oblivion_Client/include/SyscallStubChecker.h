#pragma once
#include "IDetector.h"
#include <string>
#include <vector>
#include <array>
#include <mutex>

namespace OblivionEye {
    class SyscallStubChecker : public IDetector {
    public:
        static SyscallStubChecker& Instance();
        const wchar_t* Name() const override { return L"SyscallStubChecker"; }
        unsigned IntervalMs() const override { return 90000; }
        void Tick() override; // integrity check
        void Start(unsigned intervalMs = 90000) { (void)intervalMs; }
        void Stop() {}
    private:
        SyscallStubChecker() = default;
        struct StubEntry { std::wstring name; std::vector<uint8_t> bytes; std::array<uint8_t,32> hmac{}; bool captured=false; };
        bool m_initialized=false;
        std::vector<StubEntry> m_stubs;
        std::mutex m_mtx;
        void CaptureBaseline();
        void Check();
        bool CaptureNtExports();
        void ComputeHmac(StubEntry& s);
        bool VerifyHmac(const StubEntry& s) const;
        std::vector<uint8_t> BuildHmacData(const StubEntry& s) const;
        void Sha256(const uint8_t* data,size_t len,uint8_t out[32]) const;
        void HmacSha256(const uint8_t* key,size_t keyLen,const uint8_t* data,size_t dataLen,uint8_t out[32]) const;
        void ObfuscatedKey(std::vector<uint8_t>& out) const;
        void SaveBaseline();
        void LoadBaseline();
        bool MapFreshNtdll(std::vector<uint8_t>& textCopy) const; // optional fresh copy compare
    };
}
