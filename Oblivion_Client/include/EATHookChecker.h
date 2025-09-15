#pragma once
#include "IDetector.h"
#include <string>
#include <vector>
#include <mutex>
#include <array>

namespace OblivionEye {
    // Memeriksa integritas Export Address Table (EAT) beberapa modul inti.
    class EATHookChecker : public IDetector {
    public:
        static EATHookChecker& Instance();
        const wchar_t* Name() const override { return L"EATHookChecker"; }
        unsigned IntervalMs() const override { return 60000; }
        void Tick() override;
        void Start(unsigned intervalMs = 60000) { (void)intervalMs; }
        void Stop() {}
    private:
        EATHookChecker() = default;
        struct ModuleBaseline {
            std::wstring name;            // lowercase module name
            bool captured = false;
            unsigned long long eatHash = 0ULL; // hash tabel alamat fungsi eksport (FNV64)
            std::vector<unsigned long> rvas;   // baseline tiap entry
            std::array<uint8_t,32> hmac{};     // HMAC-SHA256 atas (name+eatHash+rvas)
            bool hmacValid = false;
        };
        void CaptureBaselines();
        void CheckModules();
        bool CaptureModule(const std::wstring& modName, ModuleBaseline& out);
        bool CheckModule(ModuleBaseline& base);
        void SaveBaselines();
        void LoadBaselines();
        void ComputeHmac(ModuleBaseline& b);
        bool VerifyHmac(const ModuleBaseline& b);
        std::vector<uint8_t> BuildHmacData(const ModuleBaseline& b) const;
        void HmacSha256(const uint8_t* key, size_t keyLen, const uint8_t* data, size_t dataLen, uint8_t out[32]);
        void Sha256(const uint8_t* data, size_t len, uint8_t out[32]);
        void ObfuscatedKey(std::vector<uint8_t>& out); // bangun secret key runtime
        std::wstring HmacToHex(const std::array<uint8_t,32>& h) const;
        bool HexToHmac(const std::wstring& hex, std::array<uint8_t,32>& h) const;
        std::vector<ModuleBaseline> m_modules; // modul yang dipantau
        std::mutex m_mtx;
        bool m_initialized = false;
    };
}
