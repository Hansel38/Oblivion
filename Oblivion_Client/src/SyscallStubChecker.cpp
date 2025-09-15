#include "../pch.h"
#include "../include/SyscallStubChecker.h"
#include "../include/Config.h"
#include "../include/Logger.h"
#include "../include/EventReporter.h"
#include "../include/DetectionCorrelator.h"
#include "../include/Utils.h"
#include <windows.h>
#include <psapi.h>
#include <vector>
#include <string>
#include <sstream>
#include <fstream>
#include <iomanip>

#pragma comment(lib, "psapi.lib")

#ifdef min
#undef min
#endif
#ifdef max
#undef max
#endif

namespace OblivionEye {
namespace {
    // --- Mini SHA256 ---
    struct SHA256Ctx { uint32_t s[8]; uint64_t bits; uint8_t buf[64]; size_t idx; };
    inline uint32_t ROR32(uint32_t v, uint32_t r) { return (v >> r) | (v << (32 - r)); }

    void SHA256_Init(SHA256Ctx &c) {
        c.s[0]=0x6a09e667; c.s[1]=0xbb67ae85; c.s[2]=0x3c6ef372; c.s[3]=0xa54ff53a;
        c.s[4]=0x510e527f; c.s[5]=0x9b05688c; c.s[6]=0x1f83d9ab; c.s[7]=0x5be0cd19;
        c.bits = 0; c.idx = 0;
    }

    void SHA256_Transform(SHA256Ctx &c, const uint8_t *data) {
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
            w[i] = (data[i*4] << 24) | (data[i*4+1] << 16) | (data[i*4+2] << 8) | data[i*4+3];
        for (int i = 16; i < 64; ++i) {
            uint32_t s0 = ROR32(w[i-15],7) ^ ROR32(w[i-15],18) ^ (w[i-15] >> 3);
            uint32_t s1 = ROR32(w[i-2],17) ^ ROR32(w[i-2],19) ^ (w[i-2] >> 10);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }
        uint32_t a=c.s[0],b=c.s[1],c2=c.s[2],d=c.s[3],e=c.s[4],f=c.s[5],g=c.s[6],h=c.s[7];
        for (int i = 0; i < 64; ++i) {
            uint32_t S1 = ROR32(e,6) ^ ROR32(e,11) ^ ROR32(e,25);
            uint32_t ch = (e & f) ^ ((~e) & g);
            uint32_t t1 = h + S1 + ch + K[i] + w[i];
            uint32_t S0 = ROR32(a,2) ^ ROR32(a,13) ^ ROR32(a,22);
            uint32_t maj = (a & b) ^ (a & c2) ^ (b & c2);
            uint32_t t2 = S0 + maj;
            h=g; g=f; f=e; e=d + t1; d=c2; c2=b; b=a; a = t1 + t2;
        }
        c.s[0]+=a; c.s[1]+=b; c.s[2]+=c2; c.s[3]+=d; c.s[4]+=e; c.s[5]+=f; c.s[6]+=g; c.s[7]+=h;
    }

    void SHA256_Update(SHA256Ctx &c, const uint8_t *d, size_t l) {
        c.bits += l * 8;
        while (l) {
            size_t n = 64 - c.idx; if (n > l) n = l;
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
        for (int j = 7; j >= 0; --j)
            c.buf[56 + (7 - j)] = static_cast<uint8_t>((bits >> (j * 8)) & 0xFF);
        SHA256_Transform(c, c.buf);
        for (int k = 0; k < 8; ++k) {
            out[k*4]   = static_cast<uint8_t>(c.s[k] >> 24);
            out[k*4+1] = static_cast<uint8_t>(c.s[k] >> 16);
            out[k*4+2] = static_cast<uint8_t>(c.s[k] >> 8);
            out[k*4+3] = static_cast<uint8_t>(c.s[k]);
        }
    }

    bool IsSyscallStub(const uint8_t *p) {
    #ifdef _WIN64
        return p[0]==0x4C && p[1]==0x8B && p[2]==0xD1 && p[3]==0xB8 && p[8]==0x0F && p[9]==0x05;
    #else
        return false;
    #endif
    }

    std::string NarrowExport(const std::wstring &w) {
        std::string a; a.reserve(w.size());
        for (auto c : w) a.push_back((c >= 1 && c <= 127) ? static_cast<char>(c) : '_');
        return a;
    }

    bool HexBytePair(const wchar_t *p, uint8_t &out) {
        auto cv=[](wchar_t c)->int{ if(c>='0'&&c<='9') return c-'0'; if(c>='a'&&c<='f') return c-'a'+10; if(c>='A'&&c<='F') return c-'A'+10; return -1; };
        int hi=cv(p[0]); int lo=cv(p[1]); if(hi<0||lo<0) return false; out=static_cast<uint8_t>((hi<<4)|lo); return true;
    }
}

SyscallStubChecker &SyscallStubChecker::Instance() { static SyscallStubChecker s; return s; }

// --- Crypto wrappers ---
void SyscallStubChecker::Sha256(const uint8_t *d, size_t l, uint8_t o[32]) const {
    SHA256Ctx c; SHA256_Init(c); SHA256_Update(c, d, l); SHA256_Final(c, o);
}

void SyscallStubChecker::HmacSha256(const uint8_t *key, size_t keyLen, const uint8_t *data, size_t dataLen, uint8_t out[32]) const {
    uint8_t kopad[64]; uint8_t kipad[64]; uint8_t kh[32];
    if (keyLen > 64) { Sha256(key, keyLen, kh); key = kh; keyLen = 32; }
    memset(kipad, 0, 64); memset(kopad, 0, 64);
    memcpy(kipad, key, keyLen); memcpy(kopad, key, keyLen);
    for (int i=0;i<64;++i) { kipad[i]^=0x36; kopad[i]^=0x5c; }
    uint8_t inner[32];
    SHA256Ctx c; SHA256_Init(c); SHA256_Update(c, kipad, 64); SHA256_Update(c, data, dataLen); SHA256_Final(c, inner);
    SHA256_Init(c); SHA256_Update(c, kopad, 64); SHA256_Update(c, inner, 32); SHA256_Final(c, out);
}

void SyscallStubChecker::ObfuscatedKey(std::vector<uint8_t> &out) const {
    const uint8_t a[8]={0x21,0x43,0x65,0x87,0xA9,0xCB,0xED,0x0F};
    const uint8_t b[8]={0x10,0x32,0x54,0x76,0x98,0xBA,0xDC,0xFE};
    const uint8_t c_[8]={0x55,0xAA,0x33,0xCC,0x77,0x88,0x99,0x11};
    const uint8_t d_[8]={0x0F,0xE1,0xD2,0xC3,0xB4,0xA5,0x96,0x87};
    out.resize(32);
    for (int i=0;i<8;++i)  out[i]      = a[i]^0x5A;
    for (int i=0;i<8;++i)  out[8+i]    = b[i]^0xA5;
    for (int i=0;i<8;++i)  out[16+i]   = c_[i]^0x3C;
    for (int i=0;i<8;++i)  out[24+i]   = d_[i]^0xC3;
    for (size_t i=0;i<out.size();++i) out[i] = static_cast<uint8_t>((out[i] + static_cast<uint8_t>(i*9)) ^ 0x6D);
}

std::vector<uint8_t> SyscallStubChecker::BuildHmacData(const StubEntry &s) const {
    std::vector<uint8_t> v; v.reserve(8 + s.name.size()*2 + s.bytes.size());
    for (auto ch : s.name) { v.push_back(static_cast<uint8_t>((ch>>8)&0xFF)); v.push_back(static_cast<uint8_t>(ch&0xFF)); }
    v.push_back(static_cast<uint8_t>(s.bytes.size()));
    v.push_back(static_cast<uint8_t>(s.bytes.size()>>8));
    for (auto b : s.bytes) v.push_back(b);
    return v;
}

void SyscallStubChecker::ComputeHmac(StubEntry &s) {
    auto data = BuildHmacData(s);
    std::vector<uint8_t> key; ObfuscatedKey(key);
    HmacSha256(key.data(), key.size(), data.data(), data.size(), s.hmac.data());
    s.captured = true;
}

bool SyscallStubChecker::VerifyHmac(const StubEntry &s) const {
    if (!s.captured) return false;
    auto data = BuildHmacData(s);
    std::vector<uint8_t> key; ObfuscatedKey(key);
    uint8_t out[32];
    HmacSha256(key.data(), key.size(), data.data(), data.size(), out);
    return memcmp(out, s.hmac.data(), 32) == 0;
}

bool SyscallStubChecker::CaptureNtExports() {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll"); if (!hNtdll) return false;
    auto base = reinterpret_cast<uint8_t*>(hNtdll);
    auto dos  = reinterpret_cast<PIMAGE_DOS_HEADER>(base); if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto nt   = reinterpret_cast<PIMAGE_NT_HEADERS>(base + dos->e_lfanew); if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    auto dir  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]; if (!dir.VirtualAddress || !dir.Size) return false;
    auto exp  = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(base + dir.VirtualAddress);

    auto names = reinterpret_cast<DWORD*>(base + exp->AddressOfNames);
    auto funcs = reinterpret_cast<DWORD*>(base + exp->AddressOfFunctions);
    auto ords  = reinterpret_cast<WORD*>(base + exp->AddressOfNameOrdinals);

    size_t nameCount = exp->NumberOfNames;
    constexpr size_t MAX_CAPTURE = OblivionEye::Config::CAPTURE_MAX;
    size_t captured = 0;

    for (size_t i = 0; i < nameCount && captured < MAX_CAPTURE; ++i) {
        const char *cname = reinterpret_cast<const char*>(base + names[i]);
        if (!cname || cname[0] != 'N' || cname[1] != 't')
            continue; // only Nt* exports
        DWORD rva = funcs[ords[i]];
        auto p = base + rva;
        if (!IsSyscallStub(p))
            continue;
        StubEntry e;
        std::wstring wname;
        while (*cname) wname.push_back(static_cast<wchar_t>(*cname++));
        e.name = wname;
        e.bytes.assign(p, p + 16); // capture first 16 bytes
        ComputeHmac(e);
        m_stubs.push_back(std::move(e));
        ++captured;
    }

    Log(L"SyscallStubChecker captured stubs=" + std::to_wstring(m_stubs.size()));
    return !m_stubs.empty();
}

void SyscallStubChecker::SaveBaseline() {
    std::wofstream f(L"syscall_stubs.dat", std::ios::trunc);
    if (!f) return;
    for (auto &s : m_stubs) {
        if (!s.captured) continue;
        f << s.name << L" ";
        std::wstringstream hs; hs << std::hex << std::setfill(L'0');
        for (auto b : s.hmac) hs << std::setw(2) << static_cast<int>(b);
        std::wstring hhex = hs.str();
        f << hhex << L" ";
        std::wstringstream bs; bs << std::hex << std::setfill(L'0');
        for (auto b : s.bytes) bs << std::setw(2) << static_cast<int>(b) << L" ";
        f << bs.str() << L"\n";
    }
}

void SyscallStubChecker::LoadBaseline() {
    std::wifstream f(L"syscall_stubs.dat");
    if (!f) return;
    std::wstring name;
    while (f >> name) {
        std::wstring hhex; if (!(f >> hhex)) break;
        StubEntry e; e.name = name;
        if (hhex.size() != 64) break;
        for (size_t i = 0; i < 32; ++i) {
            uint8_t b = 0; if (!HexBytePair(hhex.c_str() + i*2, b)) { e.captured = false; break; }
            e.hmac[i] = b;
        }
        std::wstring bytesLine;
        if (!std::getline(f, bytesLine)) break;
        if (bytesLine.empty()) continue;
        std::wstringstream ss(bytesLine);
        std::wstring tok;
        while (ss >> tok) {
            if (tok.size() != 2) continue;
            uint8_t bv = 0; if (!HexBytePair(tok.c_str(), bv)) continue;
            e.bytes.push_back(bv);
        }
        if (!e.bytes.empty() && VerifyHmac(e)) { e.captured = true; m_stubs.push_back(e); }
    }
}

bool SyscallStubChecker::MapFreshNtdll(std::vector<uint8_t> &out) const {
    wchar_t sysDir[MAX_PATH]; if (!GetSystemDirectoryW(sysDir, MAX_PATH)) return false;
    std::wstring path = std::wstring(sysDir) + L"\\ntdll.dll";
    HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;
    HANDLE hMap = CreateFileMappingW(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!hMap) { CloseHandle(hFile); return false; }
    void *view = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if (!view) { CloseHandle(hMap); CloseHandle(hFile); return false; }

    auto base = static_cast<uint8_t*>(view);
    auto dos  = reinterpret_cast<PIMAGE_DOS_HEADER>(base); if (dos->e_magic != IMAGE_DOS_SIGNATURE) { UnmapViewOfFile(view); CloseHandle(hMap); CloseHandle(hFile); return false; }
    auto nt   = reinterpret_cast<PIMAGE_NT_HEADERS>(base + dos->e_lfanew);
    size_t imageSize = nt->OptionalHeader.SizeOfImage;
    out.assign(base, base + imageSize);

    UnmapViewOfFile(view); CloseHandle(hMap); CloseHandle(hFile);
    return true;
}

void SyscallStubChecker::CaptureBaseline() {
    if (m_initialized) return;
    m_stubs.clear();
    if (!CaptureNtExports()) return;
    SaveBaseline();
    m_initialized = true;
}

void SyscallStubChecker::Check() {
    if (!m_initialized) return;

    std::vector<uint8_t> fresh; bool haveFresh = MapFreshNtdll(fresh);

    for (auto &s : m_stubs) {
        if (!s.captured) continue;

        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll"); if (!hNtdll) return;
        std::string ansiName = NarrowExport(s.name);
        FARPROC fp = GetProcAddress(hNtdll, ansiName.c_str()); if (!fp) continue;
        auto p = reinterpret_cast<uint8_t*>(fp);

        bool mismatch = false;
        for (size_t i = 0; i < s.bytes.size(); ++i) {
            if (p[i] != s.bytes[i]) { mismatch = true; break; }
        }

        if (!mismatch && haveFresh) {
            // Compare against clean mapped copy by scanning export again for RVA
            auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(hNtdll);
            auto nt  = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<uint8_t*>(hNtdll) + dos->e_lfanew);
            auto dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
            auto exp = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(reinterpret_cast<uint8_t*>(hNtdll) + dir.VirtualAddress);
            auto names = reinterpret_cast<DWORD*>(reinterpret_cast<uint8_t*>(hNtdll) + exp->AddressOfNames);
            auto funcs = reinterpret_cast<DWORD*>(reinterpret_cast<uint8_t*>(hNtdll) + exp->AddressOfFunctions);
            auto ords  = reinterpret_cast<WORD*>(reinterpret_cast<uint8_t*>(hNtdll) + exp->AddressOfNameOrdinals);
            for (size_t i = 0; i < exp->NumberOfNames; ++i) {
                const char *cname = reinterpret_cast<const char*>(reinterpret_cast<uint8_t*>(hNtdll) + names[i]);
                if (_stricmp(cname, ansiName.c_str()) == 0) {
                    DWORD rva = funcs[ords[i]];
                    if (rva < fresh.size()) {
                        const uint8_t *clean = &fresh[rva];
                        for (size_t k = 0; k < s.bytes.size(); ++k) {
                            if (clean[k] != s.bytes[k]) { mismatch = true; break; }
                        }
                    }
                    break;
                }
            }
        }

        if (mismatch) {
            std::wstring msg = L"Syscall stub mismatch: " + s.name;
            DetectionCorrelator::Instance().Report(L"SYSCALL", msg);
            EventReporter::SendDetection(L"SyscallStubChecker", msg);
            ShowDetectionAndExit(msg);
            return;
        }
    }
}

void SyscallStubChecker::Tick() {
    std::lock_guard<std::mutex> lk(m_mtx);
    if (!m_initialized) CaptureBaseline(); else Check();
}
}
