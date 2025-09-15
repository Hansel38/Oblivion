#include "../pch.h"
#include "../include/EATHookChecker.h"
#include "../include/Logger.h"
#include "../include/EventReporter.h"
#include "../include/Utils.h"
#include "../include/DetectionCorrelator.h"
#include <windows.h>
#include <psapi.h>
#include <vector>
#include <string>
#include <algorithm>
#include <sstream>
#include <fstream>
#include <iomanip>
#include <array>
#include <cstring>

#pragma comment(lib, "psapi.lib")

#ifdef min
#undef min
#endif
#ifdef max
#undef max
#endif

namespace OblivionEye {
namespace {
    // --- Hash helpers ---
    constexpr unsigned long long FNV_OFFSET = 1469598103934665603ULL;
    constexpr unsigned long long FNV_PRIME  = 1099511628211ULL;

    unsigned long long Fnv1a64(const unsigned char *data, size_t len) {
        unsigned long long h = FNV_OFFSET;
        for (size_t i = 0; i < len; ++i) {
            h ^= data[i];
            h *= FNV_PRIME;
        }
        return h;
    }

    std::wstring Hex32(unsigned long v) {
        wchar_t buf[16];
        swprintf(buf, 16, L"%08lX", v);
        return buf;
    }

    // --- Minimal SHA256 implementation (kept local) ---
    struct SHA256Ctx { uint32_t s[8]; uint64_t bits; uint8_t buf[64]; size_t idx; };
    inline uint32_t ROR(uint32_t v, uint32_t r) { return (v >> r) | (v << (32 - r)); }

    void SHA256_Init(SHA256Ctx &c) {
        c.s[0]=0x6a09e667; c.s[1]=0xbb67ae85; c.s[2]=0x3c6ef372; c.s[3]=0xa54ff53a;
        c.s[4]=0x510e527f; c.s[5]=0x9b05688c; c.s[6]=0x1f83d9ab; c.s[7]=0x5be0cd19;
        c.bits = 0; c.idx = 0;
    }

    void SHA256_Transform(SHA256Ctx &c, const uint8_t *d) {
        static const uint32_t K[64] = {
            0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
            0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
            0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
            0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
            0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
            0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
            0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
            0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
        };
        uint32_t w[64];
        for (int i = 0; i < 16; ++i)
            w[i] = (d[i*4] << 24) | (d[i*4+1] << 16) | (d[i*4+2] << 8) | d[i*4+3];
        for (int i = 16; i < 64; ++i) {
            uint32_t s0 = ROR(w[i-15],7) ^ ROR(w[i-15],18) ^ (w[i-15] >> 3);
            uint32_t s1 = ROR(w[i-2],17) ^ ROR(w[i-2],19) ^ (w[i-2] >> 10);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }
        uint32_t a=c.s[0],b=c.s[1],c2=c.s[2],d2=c.s[3],e=c.s[4],f=c.s[5],g=c.s[6],h=c.s[7];
        for (int i = 0; i < 64; ++i) {
            uint32_t S1 = ROR(e,6) ^ ROR(e,11) ^ ROR(e,25);
            uint32_t ch = (e & f) ^ ((~e) & g);
            uint32_t t1 = h + S1 + ch + K[i] + w[i];
            uint32_t S0 = ROR(a,2) ^ ROR(a,13) ^ ROR(a,22);
            uint32_t maj = (a & b) ^ (a & c2) ^ (b & c2);
            uint32_t t2 = S0 + maj;
            h=g; g=f; f=e; e=d2 + t1; d2=c2; c2=b; b=a; a = t1 + t2;
        }
        c.s[0]+=a; c.s[1]+=b; c.s[2]+=c2; c.s[3]+=d2; c.s[4]+=e; c.s[5]+=f; c.s[6]+=g; c.s[7]+=h;
    }

    void SHA256_Update(SHA256Ctx &c, const uint8_t *d, size_t l) {
        c.bits += l * 8;
        while (l) {
            size_t n = 64 - c.idx;
            if (n > l) n = l;
            memcpy(c.buf + c.idx, d, n);
            c.idx += n; d += n; l -= n;
            if (c.idx == 64) { SHA256_Transform(c, c.buf); c.idx = 0; }
        }
    }

    void SHA256_Final(SHA256Ctx &c, uint8_t out[32]) {
        size_t i = c.idx; c.buf[i++] = 0x80;
        if (i > 56) { while (i < 64) c.buf[i++] = 0; SHA256_Transform(c, c.buf); i = 0; }
        while (i < 56) c.buf[i++] = 0;
        uint64_t bits = c.bits;
        for (int j = 7; j >= 0; --j) c.buf[56 + (7 - j)] = static_cast<uint8_t>((bits >> (j * 8)) & 0xFF);
        SHA256_Transform(c, c.buf);
        for (int k = 0; k < 8; ++k) {
            out[k*4]   = static_cast<uint8_t>(c.s[k] >> 24);
            out[k*4+1] = static_cast<uint8_t>(c.s[k] >> 16);
            out[k*4+2] = static_cast<uint8_t>(c.s[k] >> 8);
            out[k*4+3] = static_cast<uint8_t>(c.s[k]);
        }
    }

    bool GetModuleInfoByName(const std::wstring &lowName, HMODULE &hOut) {
        HMODULE mods[768] = {}; DWORD needed = 0;
        if (!EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &needed)) return false;
        int count = static_cast<int>(needed / sizeof(HMODULE));
        wchar_t name[MAX_PATH];
        for (int i = 0; i < count; ++i) {
            if (GetModuleBaseNameW(GetCurrentProcess(), mods[i], name, MAX_PATH)) {
                std::wstring ln = ToLower(name);
                if (ln == lowName) { hOut = mods[i]; return true; }
            }
        }
        return false;
    }
}

// --- Public singleton ---
EATHookChecker &EATHookChecker::Instance() { static EATHookChecker s; return s; }

// --- Crypto wrappers ---
void EATHookChecker::Sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
    SHA256Ctx c; SHA256_Init(c); SHA256_Update(c, data, len); SHA256_Final(c, out);
}

void EATHookChecker::HmacSha256(const uint8_t *key, size_t keyLen, const uint8_t *data, size_t dataLen, uint8_t out[32]) {
    uint8_t kopad[64];
    uint8_t kipad[64];
    uint8_t khash[32];
    if (keyLen > 64) { Sha256(key, keyLen, khash); key = khash; keyLen = 32; }
    memset(kipad, 0, 64); memset(kopad, 0, 64);
    memcpy(kipad, key, keyLen); memcpy(kopad, key, keyLen);
    for (int i = 0; i < 64; ++i) { kipad[i] ^= 0x36; kopad[i] ^= 0x5c; }
    uint8_t inner[32];
    SHA256Ctx c; SHA256_Init(c); SHA256_Update(c, kipad, 64); SHA256_Update(c, data, dataLen); SHA256_Final(c, inner);
    SHA256_Init(c); SHA256_Update(c, kopad, 64); SHA256_Update(c, inner, 32); SHA256_Final(c, out);
}

void EATHookChecker::ObfuscatedKey(std::vector<uint8_t> &out) {
    const unsigned char p1[8]={0x13,0x37,0xC0,0xDE,0x42,0x21,0x5A,0x9F};
    const unsigned char p2[8]={0xA1,0xB2,0xC3,0xD4,0x55,0x66,0x77,0x88};
    const unsigned char p3[8]={0x10,0x20,0x30,0x40,0x50,0x60,0x70,0x80};
    const unsigned char p4[8]={0x99,0xAB,0xCD,0xEF,0x11,0x22,0x33,0x44};
    out.resize(32);
    for(int i=0;i<8;++i)  out[i]      = static_cast<uint8_t>(p1[i]^0x5A);
    for(int i=0;i<8;++i)  out[8+i]    = static_cast<uint8_t>(p2[i]^0xA5);
    for(int i=0;i<8;++i)  out[16+i]   = static_cast<uint8_t>(p3[i]^0x3C);
    for(int i=0;i<8;++i)  out[24+i]   = static_cast<uint8_t>(p4[i]^0xC3);
    for(size_t i=0;i<out.size();++i) out[i] = static_cast<uint8_t>((out[i] + static_cast<uint8_t>(i*17)) ^ 0xAA);
}

std::vector<uint8_t> EATHookChecker::BuildHmacData(const ModuleBaseline &b) const {
    std::vector<uint8_t> d; d.reserve(64 + b.rvas.size()*4);
    auto push64=[&](unsigned long long v){ for(int i=7;i>=0;--i) d.push_back(static_cast<uint8_t>((v>>(i*8))&0xFF)); };
    auto push32=[&](unsigned long v){ d.push_back(static_cast<uint8_t>(v>>24)); d.push_back(static_cast<uint8_t>(v>>16)); d.push_back(static_cast<uint8_t>(v>>8)); d.push_back(static_cast<uint8_t>(v)); };
    for(auto c : b.name){ d.push_back(static_cast<uint8_t>((c>>8)&0xFF)); d.push_back(static_cast<uint8_t>(c&0xFF)); }
    push64(b.eatHash);
    push64(b.rvas.size());
    for(auto r: b.rvas) push32(r);
    return d;
}

void EATHookChecker::ComputeHmac(ModuleBaseline &b) {
    auto data = BuildHmacData(b);
    std::vector<uint8_t> key; ObfuscatedKey(key);
    HmacSha256(key.data(), key.size(), data.data(), data.size(), b.hmac.data());
    b.hmacValid = true;
}

bool EATHookChecker::VerifyHmac(const ModuleBaseline &b) {
    if (!b.hmacValid) return false;
    auto data = BuildHmacData(b);
    std::vector<uint8_t> key; ObfuscatedKey(key);
    uint8_t out[32];
    HmacSha256(key.data(), key.size(), data.data(), data.size(), out);
    return memcmp(out, b.hmac.data(), 32) == 0;
}

bool EATHookChecker::CaptureModule(const std::wstring &modName, ModuleBaseline &out) {
    HMODULE hMod = nullptr;
    if (!GetModuleInfoByName(modName, hMod)) return false;

    auto base = reinterpret_cast<uint8_t*>(hMod);
    auto dos  = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto nt   = reinterpret_cast<PIMAGE_NT_HEADERS>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    auto dir  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir.VirtualAddress || !dir.Size) return false;

    auto expDir   = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(base + dir.VirtualAddress);
    auto functions= reinterpret_cast<DWORD*>(base + expDir->AddressOfFunctions);
    size_t count  = expDir->NumberOfFunctions;
    if (!count) return false;

    out.rvas.assign(functions, functions + count);
    out.eatHash = Fnv1a64(reinterpret_cast<unsigned char*>(functions), sizeof(DWORD) * count);
    ComputeHmac(out);
    out.captured = true;
    return true;
}

std::wstring EATHookChecker::HmacToHex(const std::array<uint8_t,32> &h) const {
    std::wstringstream ss; ss << std::hex << std::setfill(L'0');
    for (auto b : h) ss << std::setw(2) << static_cast<int>(b);
    return ss.str();
}

bool EATHookChecker::HexToHmac(const std::wstring &hex, std::array<uint8_t,32> &h) const {
    if (hex.size() != 64) return false;
    auto cv = [](wchar_t c)->int{
        if(c>='0'&&c<='9') return c-'0';
        if(c>='a'&&c<='f') return c-'a'+10;
        if(c>='A'&&c<='F') return c-'A'+10;
        return -1;
    };
    for (size_t i = 0; i < 32; ++i) {
        int hi = cv(hex[i*2]); int lo = cv(hex[i*2+1]);
        if (hi < 0 || lo < 0) return false;
        h[i] = static_cast<uint8_t>((hi<<4)|lo);
    }
    return true;
}

void EATHookChecker::SaveBaselines() {
    std::wofstream f(L"eat_baseline.txt", std::ios::trunc);
    if (!f) return;
    for (auto &m : m_modules) {
        if (!m.captured || !m.hmacValid) continue;
        f << m.name << L" " << m.eatHash << L" " << HmacToHex(m.hmac);
        for (auto r : m.rvas) f << L" " << r;
        f << L"\n";
    }
}

void EATHookChecker::LoadBaselines() {
    std::wifstream f(L"eat_baseline.txt");
    if (!f) return;
    std::wstring line;
    while (std::getline(f, line)) {
        if (line.empty()) continue;
        std::wstringstream ss(line);
        ModuleBaseline b; std::wstring hhex;
        ss >> b.name >> b.eatHash >> hhex;
        if (b.name.empty() || b.eatHash == 0 || hhex.size() != 64) continue;
        unsigned long rv;
        while (ss >> rv) b.rvas.push_back(rv);
        if (!HexToHmac(hhex, b.hmac)) continue;
        b.hmacValid = true;
        if (!VerifyHmac(b)) {
            Log(L"EATHookChecker HMAC mismatch for " + b.name + L"; ignoring baseline entry");
            continue;
        }
        b.captured = true;
        m_modules.push_back(b);
    }
}

bool EATHookChecker::CheckModule(ModuleBaseline &base) {
    HMODULE hMod = nullptr;
    if (!GetModuleInfoByName(base.name, hMod)) return false;

    auto bptr = reinterpret_cast<uint8_t*>(hMod);
    auto dos  = reinterpret_cast<PIMAGE_DOS_HEADER>(bptr); if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto nt   = reinterpret_cast<PIMAGE_NT_HEADERS>(bptr + dos->e_lfanew); if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    auto dir  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]; if (!dir.VirtualAddress || !dir.Size) return false;
    auto exp  = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(bptr + dir.VirtualAddress);
    auto functions = reinterpret_cast<DWORD*>(bptr + exp->AddressOfFunctions);
    size_t count = exp->NumberOfFunctions; if (!count) return false;

    unsigned long long curHash = Fnv1a64(reinterpret_cast<unsigned char*>(functions), sizeof(DWORD) * count);
    if (curHash == base.eatHash && count == base.rvas.size())
        return true; // unchanged

    // Build diff
    size_t minCount = (std::min)(count, base.rvas.size());
    std::wstringstream diff;
    for (size_t i = 0; i < minCount; ++i) {
        if (functions[i] != base.rvas[i])
            diff << L"#" << i << L"(" << Hex32(base.rvas[i]) << L"->" << Hex32(functions[i]) << L") ";
    }
    if (count != base.rvas.size())
        diff << L"countChanged(" << base.rvas.size() << L"->" << count << L")";

    if (diff.tellp() > 0) {
        std::wstring msg = L"EAT modified: " + base.name + L" " + diff.str();
        DetectionCorrelator::Instance().Report(L"EAT", msg);
        EventReporter::SendDetection(L"EATHookChecker", msg);
        ShowDetectionAndExit(msg);
        return false;
    }
    return true;
}

void EATHookChecker::CaptureBaselines() {
    std::lock_guard<std::mutex> lk(m_mtx);
    if (m_initialized) return;

    if (m_modules.empty()) {
        m_modules = {
            {L"kernel32.dll"}, {L"user32.dll"}, {L"gdi32.dll"},
            {L"ntdll.dll"}, {L"ws2_32.dll"}, {L"advapi32.dll"}
        };
    }
    for (auto &m : m_modules) m.name = ToLower(m.name);

    if (_waccess(L"eat_baseline.txt", 0) == 0)
        LoadBaselines();

    for (auto &m : m_modules) {
        if (!m.captured) {
            if (CaptureModule(m.name, m))
                Log(L"EATHookChecker baseline " + m.name + L" captured");
            else
                Log(L"EATHookChecker failed capture baseline " + m.name);
        }
    }

    SaveBaselines();
    m_initialized = true;
}

void EATHookChecker::CheckModules() {
    std::lock_guard<std::mutex> lk(m_mtx);
    for (auto &m : m_modules) {
        if (!m.captured) continue;
        CheckModule(m);
    }
}

void EATHookChecker::Tick() {
    if (!m_initialized) CaptureBaselines(); else CheckModules();
}
}
