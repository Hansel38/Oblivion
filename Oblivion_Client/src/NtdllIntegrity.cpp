#include "../pch.h"
#include "../include/NtdllIntegrity.h"
#include "../include/Logger.h"
#include "../include/EventReporter.h"
#include "../include/Utils.h"
#include "../include/IntegrityChunkWhitelist.h"
#include "../include/Config.h"
#include "../include/HWID.h"
#include "../include/HashUtil.h"
#include <windows.h>
#include <string>
#include <sstream>
#include <iomanip>
#include <fstream>

namespace OblivionEye {
namespace {
    unsigned long long TruncSha256_64(const unsigned char *data, size_t len) {
        // Use existing local SHA256 (later replaced by centralized HashUtil) and take first 8 bytes LE
        unsigned char full[32];
        // Reuse local minimal implementation via helper below (Sha256 wrapper defined later) OR fallback simple
        // We'll call NtdllIntegrity::Sha256 via a lambda requiring an instance not yet created; replicate minimal tiny call here.
        // Simpler: copy mini hashing using same routines below once we have function pointer? For clarity we allocate a temp context.
        // We'll temporarily create a context and reuse code; duplicating minimal pieces would bloat so call through a static function outside class? For brevity, we fallback to FNV if fail.
        // Since our local SHA256 functions appear after this static function, we cannot directly call them; implement miniature dispatcher by forward declare.
        // Simpler path: keep old FNV for failure path only.
        // We'll implement a static inline performing SHA256 using same code below by copying necessary lines (acceptable minimal duplication).
        struct SHA256CtxLocal { uint32_t s[8]; uint64_t bits; uint8_t buf[64]; size_t idx; };
        auto ROR32L = [](uint32_t v, uint32_t r){ return (v >> r) | (v << (32 - r)); };
        auto init=[&](SHA256CtxLocal &c){ c.s[0]=0x6a09e667; c.s[1]=0xbb67ae85; c.s[2]=0x3c6ef372; c.s[3]=0xa54ff53a; c.s[4]=0x510e527f; c.s[5]=0x9b05688c; c.s[6]=0x1f83d9ab; c.s[7]=0x5be0cd19; c.bits=0; c.idx=0; };
        auto transform=[&](SHA256CtxLocal &c,const uint8_t *d){ static const uint32_t K[64]={0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2}; uint32_t w[64]; for(int i=0;i<16;++i) w[i]=(d[i*4]<<24)|(d[i*4+1]<<16)|(d[i*4+2]<<8)|d[i*4+3]; for(int i=16;i<64;++i){ uint32_t s0=ROR32L(w[i-15],7)^ROR32L(w[i-15],18)^(w[i-15]>>3); uint32_t s1=ROR32L(w[i-2],17)^ROR32L(w[i-2],19)^(w[i-2]>>10); w[i]=w[i-16]+s0+w[i-7]+s1; } uint32_t a=c.s[0],b=c.s[1],c2=c.s[2],d2=c.s[3],e=c.s[4],f=c.s[5],g=c.s[6],h=c.s[7]; for(int i=0;i<64;++i){ uint32_t S1=ROR32L(e,6)^ROR32L(e,11)^ROR32L(e,25); uint32_t ch=(e&f)^((~e)&g); uint32_t t1=h+S1+ch+K[i]+w[i]; uint32_t S0=ROR32L(a,2)^ROR32L(a,13)^ROR32L(a,22); uint32_t maj=(a&b)^(a&c2)^(b&c2); uint32_t t2=S0+maj; h=g; g=f; f=e; e=d2+t1; d2=c2; c2=b; b=a; a=t1+t2; } c.s[0]+=a; c.s[1]+=b; c.s[2]+=c2; c.s[3]+=d2; c.s[4]+=e; c.s[5]+=f; c.s[6]+=g; c.s[7]+=h; };
        auto update=[&](SHA256CtxLocal &c,const uint8_t *d,size_t l){ c.bits+=l*8; while(l){ size_t n=64-c.idx; if(n>l) n=l; memcpy(c.buf+c.idx,d,n); c.idx+=n; d+=n; l-=n; if(c.idx==64){ transform(c,c.buf); c.idx=0; } } };
        auto final=[&](SHA256CtxLocal &c,uint8_t out[32]){ size_t i=c.idx; c.buf[i++]=0x80; if(i>56){ while(i<64)c.buf[i++]=0; transform(c,c.buf); i=0; } while(i<56)c.buf[i++]=0; uint64_t bits=c.bits; for(int j=7;j>=0;--j)c.buf[56+(7-j)]=static_cast<uint8_t>((bits>>(j*8))&0xFF); transform(c,c.buf); for(int k=0;k<8;++k){ out[k*4]=static_cast<uint8_t>(c.s[k]>>24); out[k*4+1]=static_cast<uint8_t>(c.s[k]>>16); out[k*4+2]=static_cast<uint8_t>(c.s[k]>>8); out[k*4+3]=static_cast<uint8_t>(c.s[k]); } };
        SHA256CtxLocal ctx; init(ctx); update(ctx,data,len); final(ctx,full); unsigned long long v=0; for(int i=0;i<8;++i) v |= (unsigned long long)full[i] << (i*8); return v;
    }

    bool GetNtdllTextRegion(unsigned char *&base, size_t &size) {
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll"); if (!hNtdll) return false;
        auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(hNtdll); if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
        auto nt  = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<unsigned char*>(hNtdll) + dos->e_lfanew); if (!nt || nt->Signature != IMAGE_NT_SIGNATURE) return false;
        auto sec = IMAGE_FIRST_SECTION(nt);
        for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
            const char *name = reinterpret_cast<const char*>(sec[i].Name);
            if (strncmp(name, ".text", 5) == 0) {
                base = reinterpret_cast<unsigned char*>(hNtdll) + sec[i].VirtualAddress;
                size = sec[i].Misc.VirtualSize ? sec[i].Misc.VirtualSize : sec[i].SizeOfRawData;
                return true;
            }
        }
        return false;
    }

    // SHA256/HMAC minimal
    struct SHA256Ctx { uint32_t s[8]; uint64_t bits; uint8_t buf[64]; size_t idx; };
    inline uint32_t ROR32(uint32_t v, uint32_t r) { return (v >> r) | (v << (32 - r)); }

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
        for (int i=0;i<16;++i)
            w[i] = (d[i*4]<<24)|(d[i*4+1]<<16)|(d[i*4+2]<<8)|d[i*4+3];
        for (int i=16;i<64;++i) {
            uint32_t s0 = ROR32(w[i-15],7)^ROR32(w[i-15],18)^(w[i-15]>>3);
            uint32_t s1 = ROR32(w[i-2],17)^ROR32(w[i-2],19)^(w[i-2]>>10);
            w[i] = static_cast<uint32_t>(w[i-16] + s0 + w[i-7] + s1);
        }
        uint32_t a=c.s[0],b=c.s[1],c2=c.s[2],d2=c.s[3],e=c.s[4],f=c.s[5],g=c.s[6],h=c.s[7];
        for (int i=0;i<64;++i) {
            uint32_t S1=ROR32(e,6)^ROR32(e,11)^ROR32(e,25);
            uint32_t ch=(e&f)^((~e)&g);
            uint32_t t1 = static_cast<uint32_t>(h + S1 + ch + K[i] + w[i]);
            uint32_t S0=ROR32(a,2)^ROR32(a,13)^ROR32(a,22);
            uint32_t maj=(a&b)^(a&c2)^(b&c2);
            uint32_t t2 = static_cast<uint32_t>(S0 + maj);
            h=g; g=f; f=e; e = static_cast<uint32_t>(d2 + t1); d2=c2; c2=b; b=a; a = static_cast<uint32_t>(t1 + t2);
        }
        c.s[0]+=a; c.s[1]+=b; c.s[2]+=c2; c.s[3]+=d2; c.s[4]+=e; c.s[5]+=f; c.s[6]+=g; c.s[7]+=h;
    }

    void SHA256_Update(SHA256Ctx &c, const uint8_t *d, size_t l) {
        c.bits += l * 8;
        while (l) {
            size_t n=64-c.idx; if (n>l) n=l; memcpy(c.buf+c.idx,d,n); c.idx+=n; d+=n; l-=n; if (c.idx==64){ SHA256_Transform(c,c.buf); c.idx=0; }
        }
    }

    void SHA256_Final(SHA256Ctx &c, uint8_t out[32]) {
        size_t i=c.idx; c.buf[i++]=0x80; if(i>56){ while(i<64)c.buf[i++]=0; SHA256_Transform(c,c.buf); i=0; } while(i<56)c.buf[i++]=0; uint64_t bits=c.bits; for(int j=7;j>=0;--j)c.buf[56+(7-j)]=static_cast<uint8_t>((bits>>(j*8))&0xFF); SHA256_Transform(c,c.buf); for(int k=0;k<8;++k){ out[k*4]=static_cast<uint8_t>(c.s[k]>>24); out[k*4+1]=static_cast<uint8_t>(c.s[k]>>16); out[k*4+2]=static_cast<uint8_t>(c.s[k]>>8); out[k*4+3]=static_cast<uint8_t>(c.s[k]); }
    }
}

void NtdllIntegrity::Sha256(const unsigned char *data, size_t len, unsigned char out[32]) const { SHA256Ctx c; SHA256_Init(c); SHA256_Update(c,data,len); SHA256_Final(c,out); }

void NtdllIntegrity::HmacSha256(const unsigned char *key,size_t keyLen,const unsigned char *data,size_t dataLen,unsigned char out[32]) const {
    unsigned char kopad[64]; unsigned char kipad[64]; unsigned char kh[32];
    if (keyLen>64) { Sha256(key,keyLen,kh); key=kh; keyLen=32; }
    memset(kipad,0,64); memset(kopad,0,64); memcpy(kipad,key,keyLen); memcpy(kopad,key,keyLen);
    for(int i=0;i<64;++i){ kipad[i]^=0x36; kopad[i]^=0x5c; }
    unsigned char inner[32];
    SHA256Ctx c; SHA256_Init(c); SHA256_Update(c,kipad,64); SHA256_Update(c,data,dataLen); SHA256_Final(c,inner);
    SHA256_Init(c); SHA256_Update(c,kopad,64); SHA256_Update(c,inner,32); SHA256_Final(c,out);
}

void NtdllIntegrity::BuildKey(std::vector<unsigned char> &key) const {
    const unsigned char a[8]={0x42,0x55,0x90,0x11,0xA9,0x5A,0xC3,0x7E};
    const unsigned char b[8]={0x10,0x22,0x33,0x44,0x99,0x88,0x77,0x66};
    const unsigned char c_[8]={0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10};
    const unsigned char d_[8]={0x0F,0x1E,0x2D,0x3C,0x4B,0x5A,0x69,0x78};
    key.resize(32);
    for(int i=0;i<8;++i)  key[i]      = a[i]^0x5A;
    for(int i=0;i<8;++i)  key[8+i]    = b[i]^0xA5;
    for(int i=0;i<8;++i)  key[16+i]   = c_[i]^0x3C;
    for(int i=0;i<8;++i)  key[24+i]   = d_[i]^0xC3;
    for(size_t i=0;i<key.size();++i) key[i] = static_cast<unsigned char>((key[i] + static_cast<unsigned char>(i*13)) ^ 0xAA);
    // Mix in HWID truncated SHA256 (optional)
    if(OblivionEye::Config::INTEGRITY_HMAC_HWID_ENABLED_DEFAULT) {
        std::wstring hwid = GenerateHWID();
        if(!hwid.empty()) {
            // Convert to UTF-8 simplistic (narrow cast) for hashing
            std::string utf8; utf8.reserve(hwid.size()); for(auto ch: hwid) utf8.push_back(static_cast<char>(ch & 0xFF));
            unsigned char h[32]; if(HashUtil::Sha256(utf8.data(), utf8.size(), h)) {
                for(size_t i=0;i<32;++i) key[i] ^= h[i];
            }
        }
    }
}

std::vector<unsigned char> NtdllIntegrity::BuildHmacData() const {
    std::vector<unsigned char> d;
    auto push64=[&](unsigned long long v){ for(int i=7;i>=0;--i) d.push_back(static_cast<unsigned char>((v>>(i*8))&0xFF)); };
    push64(m_baselineHash);
    push64(m_chunkHashes.size()); for(auto h : m_chunkHashes) push64(h);
    push64(m_diskHash);
    push64(m_diskChunkHashes.size()); for(auto h: m_diskChunkHashes) push64(h);
    if(OblivionEye::Config::INTEGRITY_CHAIN_BASELINE_DEFAULT && m_prevChainValid) {
        d.insert(d.end(), m_prevChain.begin(), m_prevChain.end());
    }
    return d;
}

std::wstring NtdllIntegrity::HmacToHex() const {
    std::wstringstream ss; ss<<std::hex<<std::setfill(L'0');
    for(auto b: m_hmac) ss<<std::setw(2)<<static_cast<int>(b);
    return ss.str();
}

bool NtdllIntegrity::HexToHmac(const std::wstring &hex) {
    if (hex.size()!=64) return false;
    auto cv=[](wchar_t c)->int{ if(c>='0'&&c<='9') return c-'0'; if(c>='a'&&c<='f') return c-'a'+10; if(c>='A'&&c<='F') return c-'A'+10; return -1; };
    for(size_t i=0;i<32;++i){ int hi=cv(hex[i*2]); int lo=cv(hex[i*2+1]); if(hi<0||lo<0) return false; m_hmac[i]=static_cast<unsigned char>((hi<<4)|lo); }
    return true;
}

bool NtdllIntegrity::CaptureSubsectionHashes() {
    unsigned char *base=nullptr; size_t size=0; if(!GetNtdllTextRegion(base,size)) return false;
    const size_t chunk=OblivionEye::Config::CHUNK_SIZE; size_t chunks=(size+chunk-1)/chunk; m_chunkHashes.resize(chunks);
    for(size_t i=0;i<chunks;++i){ size_t off=i*chunk; size_t len=(off+chunk<=size)?chunk:(size-off); m_chunkHashes[i]=TruncSha256_64(base+off,len);} return true;
}

bool NtdllIntegrity::MapFreshDiskText(std::vector<unsigned long long> &diskChunks, unsigned long long &diskHash) const {
    wchar_t sysDir[MAX_PATH]; if(!GetSystemDirectoryW(sysDir, MAX_PATH)) return false;
    std::wstring path=std::wstring(sysDir)+L"\\ntdll.dll";
    HANDLE f=CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr); if(f==INVALID_HANDLE_VALUE) return false;
    HANDLE map=CreateFileMappingW(f,nullptr,PAGE_READONLY,0,0,nullptr); if(!map){ CloseHandle(f); return false; }
    void* view=MapViewOfFile(map,FILE_MAP_READ,0,0,0); if(!view){ CloseHandle(map); CloseHandle(f); return false; }
    unsigned char* base=(unsigned char*)view; auto dos=(PIMAGE_DOS_HEADER)base; if(dos->e_magic!=IMAGE_DOS_SIGNATURE){ UnmapViewOfFile(view); CloseHandle(map); CloseHandle(f); return false; }
    auto nt=(PIMAGE_NT_HEADERS)(base+dos->e_lfanew); auto sec=IMAGE_FIRST_SECTION(nt);
    unsigned char* textBase=nullptr; size_t textSize=0;
    for(unsigned i=0;i<nt->FileHeader.NumberOfSections;++i){ if(strncmp((const char*)sec[i].Name, ".text",5)==0){ textBase=base+sec[i].VirtualAddress; textSize=sec[i].Misc.VirtualSize?sec[i].Misc.VirtualSize:sec[i].SizeOfRawData; break; } }
    if(!textBase || !textSize){ UnmapViewOfFile(view); CloseHandle(map); CloseHandle(f); return false; }
    diskHash=TruncSha256_64(textBase,textSize);
    const size_t chunk=OblivionEye::Config::CHUNK_SIZE; size_t chunks=(textSize+chunk-1)/chunk; diskChunks.resize(chunks);
    for(size_t i=0;i<chunks;++i){ size_t off=i*chunk; size_t len=(off+chunk<=textSize)?chunk:(textSize-off); diskChunks[i]=TruncSha256_64(textBase+off,len); }
    UnmapViewOfFile(view); CloseHandle(map); CloseHandle(f); return true;
}

void NtdllIntegrity::ComputeHmac() {
    auto data=BuildHmacData(); std::vector<unsigned char> key; BuildKey(key); HmacSha256(key.data(), key.size(), data.data(), data.size(), m_hmac.data()); m_hmacValid=true;
}

bool NtdllIntegrity::VerifyHmac() const {
    if(!m_hmacValid) return false;
    auto data=BuildHmacData(); std::vector<unsigned char> key; BuildKey(key); unsigned char out[32]; HmacSha256(key.data(), key.size(), data.data(), data.size(), out); return memcmp(out,m_hmac.data(),32)==0;
}

void NtdllIntegrity::SaveBaseline() {
    std::wofstream f(L"ntdll_baseline.txt", std::ios::trunc); if(!f) return; if(!m_hmacValid) ComputeHmac();
    // File format v2: version baselineHash chunkCount chunks... diskHash diskChunkCount diskChunks... hmac prevChain(optional)
    f<<OblivionEye::Config::INTEGRITY_BASELINE_VERSION<<L" "<<m_baselineHash<<L" "<<m_chunkHashes.size(); for(auto h: m_chunkHashes) f<<L" "<<h;
    f<<L" "<<m_diskHash<<L" "<<m_diskChunkHashes.size(); for(auto h: m_diskChunkHashes) f<<L" "<<h;
    f<<L" "<<HmacToHex(); if(m_prevChainValid){ std::wstringstream pc; pc<<std::hex<<std::setfill(L'0'); for(auto b: m_prevChain) pc<<std::setw(2)<<static_cast<int>(b); f<<L" "<<pc.str(); }
    f<<L"\n";
}

bool NtdllIntegrity::LoadBaseline() {
    std::wifstream f(L"ntdll_baseline.txt"); if(!f) return false; unsigned long long chunkCount=0,diskChunkCount=0; std::wstring hhex; unsigned ver=1;
    // Peek first token, if versioned it'll be small (<=10) and followed by large baseline hash
    std::wstring first; if(!(f>>first)) return false; unsigned long long maybeHash=0ULL; try { ver=std::stoul(first); } catch(...) { ver=1; }
    if(ver==OblivionEye::Config::INTEGRITY_BASELINE_VERSION){ if(!(f>>m_baselineHash>>chunkCount)) return false; }
    else { // legacy: first token was actually baseline hash
        ver=1; try { m_baselineHash=std::stoull(first); } catch(...) { return false; } if(!(f>>chunkCount)) return false; }
    m_chunkHashes.resize(static_cast<size_t>(chunkCount)); for(size_t i=0;i<m_chunkHashes.size();++i) f>>m_chunkHashes[i];
    if(!(f>>m_diskHash>>diskChunkCount)) return false; m_diskChunkHashes.resize(static_cast<size_t>(diskChunkCount)); for(size_t i=0;i<m_diskChunkHashes.size();++i) f>>m_diskChunkHashes[i];
    if(!(f>>hhex)) return false; if(!HexToHmac(hhex)) return false; m_hmacValid=true; if(ver>=2){ std::wstring prevHex; if(f>>prevHex){ if(prevHex.size()==64){ auto cv=[](wchar_t c)->int{ if(c>='0'&&c<='9') return c-'0'; if(c>='a'&&c<='f') return c-'a'+10; if(c>='A'&&c<='F') return c-'A'+10; return -1; }; bool good=true; for(size_t i=0;i<32;++i){ int hi=cv(prevHex[i*2]); int lo=cv(prevHex[i*2+1]); if(hi<0||lo<0){ good=false; break; } m_prevChain[i]=static_cast<unsigned char>((hi<<4)|lo); } if(good) m_prevChainValid=true; } } }
    if(!VerifyHmac()){ Log(L"NtdllIntegrity baseline HMAC mismatch, ignoring stored baseline"); m_chunkHashes.clear(); m_diskChunkHashes.clear(); m_hmacValid=false; return false; }
    m_baselineCaptured=true; m_diskCaptured=true; return true;
}

void NtdllIntegrity::CaptureBaseline() {
    if(m_baselineCaptured) return; if(LoadBaseline()) { Log(L"NtdllIntegrity baseline loaded (persisted)"); return; }
    unsigned char* base=nullptr; size_t size=0; if(!GetNtdllTextRegion(base,size)) return; m_baselineHash=TruncSha256_64(base,size); CaptureSubsectionHashes();
    if(MapFreshDiskText(m_diskChunkHashes, m_diskHash)) m_diskCaptured=true; ComputeHmac(); SaveBaseline(); m_baselineCaptured=true; Log(L"NtdllIntegrity baseline captured fresh");
}

bool NtdllIntegrity::Check() {
    unsigned char* base=nullptr; size_t size=0; if(!GetNtdllTextRegion(base,size)) return false;
    // Consistent hashing: use truncated SHA256 (same as baseline capture)
    auto current = TruncSha256_64(base, size);
    if(m_baselineCaptured && current!=m_baselineHash){
        const size_t chunk=OblivionEye::Config::CHUNK_SIZE; size_t chunks=(size+chunk-1)/chunk; std::wstring deltaInfo;
        bool allDiskMatches=true; std::vector<size_t> modifiedIdx;
        for(size_t i=0;i<chunks && i<m_chunkHashes.size(); ++i){
            size_t off=i*chunk; size_t len=(off+chunk<=size)?chunk:(size-off);
            unsigned long long h = TruncSha256_64(base+off, len);
            if(h!=m_chunkHashes[i]){
                if(IntegrityChunkWhitelist::IsWhitelisted(L"ntdll.dll", i)) continue;
                modifiedIdx.push_back(i);
                deltaInfo += L"[m"+std::to_wstring(i)+L"@0x"+std::to_wstring(static_cast<unsigned long long>(off))+L"]";
                if(m_diskCaptured && i<m_diskChunkHashes.size()){
                    if(m_diskChunkHashes[i]==h) deltaInfo+=L"(=disk)"; else { deltaInfo+=L"(!disk)"; allDiskMatches=false; }
                } else allDiskMatches=false;
            }
        }
        if(deltaInfo.empty()) return false;
        if(OblivionEye::Config::INTEGRITY_AUTO_WHITELIST_DISK_MATCH_DEFAULT && !modifiedIdx.empty() && allDiskMatches){
            // Auto whitelist these indices and rebuild baseline
            for(auto idx: modifiedIdx) IntegrityChunkWhitelist::Add(L"ntdll.dll", idx);
            // Rebaseline chunk hashes to current for those indices (use truncated SHA256)
            for(auto idx: modifiedIdx){ size_t off=idx*chunk; size_t len=(off+chunk<=size)?chunk:(size-off); m_chunkHashes[idx]=TruncSha256_64(base+off,len); }
            m_baselineHash=current; ComputeHmac(); SaveBaseline(); Log(L"NtdllIntegrity auto-whitelisted disk-matching chunks: "+deltaInfo);
            return false; // suppressed detection
        }
        EventReporter::SendDetection(L"NtdllIntegrity", L"ntdll .text modified chunks:"+deltaInfo); ShowDetectionAndExit(L"ntdll integrity mismatch "+deltaInfo); return true;
    }
    return false;
}

NtdllIntegrity &NtdllIntegrity::Instance() { static NtdllIntegrity s; return s; }
void NtdllIntegrity::Tick() { if(!m_baselineCaptured) CaptureBaseline(); else Check(); }
}
