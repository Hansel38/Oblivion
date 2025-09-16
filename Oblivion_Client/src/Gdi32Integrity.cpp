#include "../pch.h"
#include "../include/Gdi32Integrity.h"
#include "../include/Logger.h"
#include "../include/EventReporter.h"
#include "../include/Utils.h"
#include "../include/IntegrityChunkWhitelist.h"
#include "../include/Config.h"
#include "../include/HashUtil.h"
#include "../include/HWID.h"
#include "../include/IntegrityHmacUtil.h"
#include "../include/IntegrityTelemetry.h"
#include "../include/RuntimeStats.h" // Diperlukan untuk RuntimeStats::Instance().IncAwGdi32()
// Catatan: Forward declaration seperti `class RuntimeStats;` TIDAK cukup di sini
// karena kita memanggil method anggota (IncAwGdi32). Forward declare hanya
// memperkenalkan nama tipe tanpa member functions. Untuk memanggil fungsi,
// definisi lengkap class dibutuhkan melalui header aslinya.
#include <windows.h>
#include <sstream>
#include <iomanip>
#include <fstream>

namespace OblivionEye {
namespace {

    std::wstring Hex64(uint64_t v) { std::wstringstream ss; ss<<std::hex<<std::setw(8)<<std::setfill(L'0')<<v; return ss.str(); }

    bool GetTextSection(const wchar_t *mod, unsigned char *&base, size_t &size) {
        HMODULE h = GetModuleHandleW(mod);
        if (!h) return false;
        auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(h);
        if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
        auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>((unsigned char*)h + dos->e_lfanew);
        if (!nt || nt->Signature != IMAGE_NT_SIGNATURE) return false;
        auto sec = IMAGE_FIRST_SECTION(nt);
        for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
            if (strncmp(reinterpret_cast<const char*>(sec[i].Name), ".text", 5) == 0) {
                base = (unsigned char*)h + sec[i].VirtualAddress;
                size = sec[i].Misc.VirtualSize ? sec[i].Misc.VirtualSize : sec[i].SizeOfRawData;
                return true;
            }
        }
        return false;
    }
    bool MapModuleTextFromDisk(const wchar_t* moduleName, std::vector<unsigned long long>& diskChunks, unsigned long long &diskHash){
        wchar_t sysDir[MAX_PATH]; if(!GetSystemDirectoryW(sysDir, MAX_PATH)) return false; std::wstring path=std::wstring(sysDir)+L"\\"+moduleName;
        HANDLE f=CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,0,nullptr); if(f==INVALID_HANDLE_VALUE) return false;
        HANDLE map=CreateFileMappingW(f,nullptr,PAGE_READONLY,0,0,nullptr); if(!map){ CloseHandle(f); return false; }
        void* view=MapViewOfFile(map,FILE_MAP_READ,0,0,0); if(!view){ CloseHandle(map); CloseHandle(f); return false; }
        unsigned char* base=(unsigned char*)view; auto dos=(PIMAGE_DOS_HEADER)base; if(dos->e_magic!=IMAGE_DOS_SIGNATURE){ UnmapViewOfFile(view); CloseHandle(map); CloseHandle(f); return false; }
        auto nt=(PIMAGE_NT_HEADERS)(base+dos->e_lfanew); auto sec=IMAGE_FIRST_SECTION(nt); unsigned char* textBase=nullptr; size_t textSize=0;
        for(unsigned i=0;i<nt->FileHeader.NumberOfSections;++i){ if(strncmp((const char*)sec[i].Name, ".text",5)==0){ textBase=base+sec[i].VirtualAddress; textSize=sec[i].Misc.VirtualSize?sec[i].Misc.VirtualSize:sec[i].SizeOfRawData; break; } }
        if(!textBase||!textSize){ UnmapViewOfFile(view); CloseHandle(map); CloseHandle(f); return false; }
        diskHash=HashUtil::Sha256Trunc64(textBase,textSize); const size_t chunk=OblivionEye::Config::CHUNK_SIZE; size_t n=(textSize+chunk-1)/chunk; diskChunks.resize(n);
        for(size_t i=0;i<n;++i){ size_t off=i*chunk; size_t len=(off+chunk<=textSize)?chunk:(textSize-off); diskChunks[i]=HashUtil::Sha256Trunc64(textBase+off,len); }
        UnmapViewOfFile(view); CloseHandle(map); CloseHandle(f); return true;
    }
}

Gdi32Integrity &Gdi32Integrity::Instance() { static Gdi32Integrity s; return s; }

bool Gdi32Integrity::CaptureSubsectionHashes() {
    unsigned char *base = nullptr; size_t size = 0;
    if (!GetTextSection(L"gdi32.dll", base, size)) return false;
    const size_t chunk = OblivionEye::Config::CHUNK_SIZE; size_t n = (size + chunk - 1) / chunk;
    m_chunkHashes.resize(n);
    for (size_t i = 0; i < n; ++i) {
        size_t off = i * chunk;
        size_t len = (off + chunk <= size) ? chunk : (size - off);
    m_chunkHashes[i] = HashUtil::Sha256Trunc64(base + off, len);
    }
    return true;
}

// HMAC helpers
void Gdi32Integrity::HmacSha256(const unsigned char *key,size_t keyLen,const unsigned char *data,size_t dataLen,unsigned char out[32]) const { IntegrityHmacUtil::HmacSha256(key,keyLen,data,dataLen,out); }
void Gdi32Integrity::BuildKey(std::vector<unsigned char>& key) const { IntegrityHmacUtil::BuildModuleKey(L"gdi32", key, true); }
std::vector<unsigned char> Gdi32Integrity::BuildHmacData() const { std::vector<unsigned char> d; auto push64=[&](unsigned long long v){ for(int i=7;i>=0;--i) d.push_back(static_cast<unsigned char>((v>>(i*8))&0xFF)); }; push64(m_baselineHash); push64(m_chunkHashes.size()); for(auto h: m_chunkHashes) push64(h); push64(m_diskHash); push64(m_diskChunkHashes.size()); for(auto h: m_diskChunkHashes) push64(h); if(OblivionEye::Config::INTEGRITY_CHAIN_BASELINE_DEFAULT && m_prevChainValid) d.insert(d.end(), m_prevChain.begin(), m_prevChain.end()); return d; }
std::wstring Gdi32Integrity::HmacToHex() const { std::wstringstream ss; ss<<std::hex<<std::setfill(L'0'); for(auto b: m_hmac) ss<<std::setw(2)<<static_cast<int>(b); return ss.str(); }
bool Gdi32Integrity::HexToHmac(const std::wstring& hex){ if(hex.size()!=64) return false; auto cv=[](wchar_t c)->int{ if(c>='0'&&c<='9') return c-'0'; if(c>='a'&&c<='f') return c-'a'+10; if(c>='A'&&c<='F') return c-'A'+10; return -1; }; for(size_t i=0;i<32;++i){ int hi=cv(hex[i*2]); int lo=cv(hex[i*2+1]); if(hi<0||lo<0) return false; m_hmac[i]=static_cast<unsigned char>((hi<<4)|lo);} return true; }
void Gdi32Integrity::ComputeHmac(){ auto data=BuildHmacData(); std::vector<unsigned char> key; BuildKey(key); HmacSha256(key.data(), key.size(), data.data(), data.size(), m_hmac.data()); m_hmacValid=true; }
bool Gdi32Integrity::VerifyHmac() const { if(!m_hmacValid) return false; auto data=BuildHmacData(); std::vector<unsigned char> key; BuildKey(key); unsigned char out[32]; HmacSha256(key.data(), key.size(), data.data(), data.size(), out); return memcmp(out,m_hmac.data(),32)==0; }
void Gdi32Integrity::SaveBaseline(){ std::wofstream f(L"gdi32_baseline.txt", std::ios::trunc); if(!f) return; if(!m_hmacValid) ComputeHmac(); f<<OblivionEye::Config::INTEGRITY_BASELINE_VERSION<<L" "<<m_baselineHash<<L" "<<m_chunkHashes.size(); for(auto h: m_chunkHashes) f<<L" "<<h; f<<L" "<<m_diskHash<<L" "<<m_diskChunkHashes.size(); for(auto h: m_diskChunkHashes) f<<L" "<<h; f<<L" "<<HmacToHex(); if(m_prevChainValid){ std::wstringstream pc; pc<<std::hex<<std::setfill(L'0'); for(auto b: m_prevChain) pc<<std::setw(2)<<static_cast<int>(b); f<<L" "<<pc.str(); } f<<L"\n"; }
bool Gdi32Integrity::LoadBaseline(){ std::wifstream f(L"gdi32_baseline.txt"); if(!f) return false; unsigned long long chunkCount=0,diskChunkCount=0; unsigned ver=1; std::wstring hhex; std::wstring first; if(!(f>>first)) return false; try { ver=std::stoul(first);} catch(...) { ver=1; } if(ver==OblivionEye::Config::INTEGRITY_BASELINE_VERSION){ if(!(f>>m_baselineHash>>chunkCount)) return false; } else { ver=1; try { m_baselineHash=std::stoull(first);} catch(...) { return false; } if(!(f>>chunkCount)) return false; } m_chunkHashes.resize(static_cast<size_t>(chunkCount)); for(size_t i=0;i<m_chunkHashes.size(); ++i) f>>m_chunkHashes[i]; if(!(f>>m_diskHash>>diskChunkCount)) return false; m_diskChunkHashes.resize(static_cast<size_t>(diskChunkCount)); for(size_t i=0;i<m_diskChunkHashes.size(); ++i) f>>m_diskChunkHashes[i]; if(!(f>>hhex)) return false; if(!HexToHmac(hhex)) return false; m_hmacValid=true; if(ver>=2){ std::wstring prevHex; if(f>>prevHex){ if(prevHex.size()==64){ auto cv=[](wchar_t c)->int{ if(c>='0'&&c<='9') return c-'0'; if(c>='a'&&c<='f') return c-'a'+10; if(c>='A'&&c<='F') return c-'A'+10; return -1; }; bool good=true; for(size_t i=0;i<32;++i){ int hi=cv(prevHex[i*2]); int lo=cv(prevHex[i*2+1]); if(hi<0||lo<0){ good=false; break; } m_prevChain[i]=static_cast<unsigned char>((hi<<4)|lo); } if(good) m_prevChainValid=true; } } } if(!VerifyHmac()){ Log(L"Gdi32Integrity baseline HMAC mismatch, ignoring stored baseline"); m_chunkHashes.clear(); m_diskChunkHashes.clear(); m_hmacValid=false; IntegrityTelemetry::Instance().Ref(L"gdi32.dll").hmacMismatch++; return false; } m_baselineCaptured=true; m_diskCaptured=true; auto &st=IntegrityTelemetry::Instance().Ref(L"gdi32.dll"); st.baselineLoadsOk++; st.hmacValid=true; st.totalChunks=(uint32_t)m_chunkHashes.size(); st.whitelistedChunks=(uint32_t)IntegrityChunkWhitelist::CountFor(L"gdi32.dll"); st.chainDepth = st.chainDepth < 1 ? (m_prevChainValid?2:1) : st.chainDepth; return true; }

void Gdi32Integrity::CaptureBaseline(){ if(m_baselineCaptured) return; if(LoadBaseline()){ Log(L"Gdi32Integrity baseline loaded (persisted)"); return; } unsigned char *base=nullptr; size_t size=0; if(!GetTextSection(L"gdi32.dll", base, size)) return; m_baselineHash=HashUtil::Sha256Trunc64(base,size); CaptureSubsectionHashes(); if(MapModuleTextFromDisk(L"gdi32.dll", m_diskChunkHashes, m_diskHash)) m_diskCaptured=true; ComputeHmac(); SaveBaseline(); m_baselineCaptured=true; Log(L"Gdi32Integrity baseline captured fresh"); auto &st=IntegrityTelemetry::Instance().Ref(L"gdi32.dll"); st.rebaselineCount++; st.baselineLoadsOk++; st.hmacValid=true; st.totalChunks=(uint32_t)m_chunkHashes.size(); st.whitelistedChunks=(uint32_t)IntegrityChunkWhitelist::CountFor(L"gdi32.dll"); st.lastBaselineTime=IntegrityTelemetry::Instance().NowIsoPublic(); }

bool Gdi32Integrity::Check() {
    unsigned char *base = nullptr; size_t size = 0;
    if (!GetTextSection(L"gdi32.dll", base, size)) return false;
    auto current = HashUtil::Sha256Trunc64(base, size);

    if (!m_baselineCaptured || current == m_baselineHash)
        return false;

    const size_t chunk = OblivionEye::Config::CHUNK_SIZE; size_t n = (size + chunk - 1) / chunk;
    std::wstring delta;
    std::vector<size_t> modifiedIdx; bool allDiskMatches=true;
    for (size_t i = 0; i < n && i < m_chunkHashes.size(); ++i) {
        size_t off = i * chunk;
        size_t len = (off + chunk <= size) ? chunk : (size - off);
        unsigned long long h = HashUtil::Sha256Trunc64(base + off, len);
        if (h != m_chunkHashes[i]) {
            if (IntegrityChunkWhitelist::IsWhitelisted(L"gdi32.dll", i)) continue;
            modifiedIdx.push_back(i);
            delta += L"[m" + std::to_wstring(i) + L"@0x" + Hex64(static_cast<uint64_t>(off)) + L"]";
            if(m_diskCaptured && i < m_diskChunkHashes.size()) {
                if(m_diskChunkHashes[i]==h) delta += L"(=disk)"; else { delta += L"(!disk)"; allDiskMatches=false; }
            } else allDiskMatches=false;
        }
    }

    if (delta.empty()) return false;
    if(OblivionEye::Config::INTEGRITY_AUTO_WHITELIST_DISK_MATCH_DEFAULT && !modifiedIdx.empty() && allDiskMatches){
        for(auto idx: modifiedIdx) IntegrityChunkWhitelist::Add(L"gdi32.dll", idx);
        for(auto idx: modifiedIdx){ size_t off=idx*chunk; size_t len=(off+chunk<=size)?chunk:(size-off); m_chunkHashes[idx]=HashUtil::Sha256Trunc64(base+off,len); }
    m_baselineHash=current; auto &st=IntegrityTelemetry::Instance().Ref(L"gdi32.dll"); if(OblivionEye::Config::INTEGRITY_CHAIN_BASELINE_DEFAULT && m_hmacValid){ m_prevChain=m_hmac; m_prevChainValid=true; st.chainAdvanceCount++; } ComputeHmac(); SaveBaseline(); st.rebaselineCount++; st.autoWhitelistCount++; st.lastAutoWhitelistTime=IntegrityTelemetry::Instance().NowIsoPublic(); st.lastBaselineTime=st.lastAutoWhitelistTime; st.whitelistedChunks=(uint32_t)IntegrityChunkWhitelist::CountFor(L"gdi32.dll"); RuntimeStats::Instance().IncAwGdi32(); Log(L"Gdi32Integrity auto-whitelisted disk-matching chunks: "+delta); return false;
    }
    EventReporter::SendDetection(L"Gdi32Integrity", L"gdi32 .text modified chunks:" + delta);
    ShowDetectionAndExit(L"gdi32 integrity mismatch " + delta);
    return true;
}

void Gdi32Integrity::Tick() { if (!m_baselineCaptured) CaptureBaseline(); else Check(); }
bool Gdi32Integrity::ForceRebaseline(){ unsigned char *base=nullptr; size_t size=0; if(!GetTextSection(L"gdi32.dll", base, size)) return false; m_baselineHash=HashUtil::Sha256Trunc64(base,size); CaptureSubsectionHashes(); std::vector<unsigned long long> diskChunks; unsigned long long diskHash=0ULL; if(MapModuleTextFromDisk(L"gdi32.dll", diskChunks, diskHash)){ m_diskChunkHashes=diskChunks; m_diskHash=diskHash; m_diskCaptured=true; } auto &st=IntegrityTelemetry::Instance().Ref(L"gdi32.dll"); if(OblivionEye::Config::INTEGRITY_CHAIN_BASELINE_DEFAULT && m_hmacValid){ m_prevChain=m_hmac; m_prevChainValid=true; st.chainAdvanceCount++; } ComputeHmac(); SaveBaseline(); m_baselineCaptured=true; st.rebaselineCount++; st.manualRebaselineCount++; st.baselineLoadsOk++; st.hmacValid=true; st.totalChunks=(uint32_t)m_chunkHashes.size(); st.whitelistedChunks=(uint32_t)IntegrityChunkWhitelist::CountFor(L"gdi32.dll"); auto nowIso=IntegrityTelemetry::Instance().NowIsoPublic(); st.lastManualRebaselineTime=nowIso; st.lastBaselineTime=nowIso; return true; }
bool Gdi32Integrity::VerifyNow(){ auto &st=IntegrityTelemetry::Instance().Ref(L"gdi32.dll"); st.verifyNowRequests++; unsigned char *base=nullptr; size_t size=0; if(!GetTextSection(L"gdi32.dll", base, size)) return false; auto current=HashUtil::Sha256Trunc64(base,size); if(!m_baselineCaptured) return false; if(current!=m_baselineHash){ st.forceVerifyFailures++; return false; } return true; }
}
