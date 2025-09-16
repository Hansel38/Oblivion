#include "../pch.h"
#include "../include/NtdllIntegrity.h"
#include "../include/Logger.h"
#include "../include/EventReporter.h"
#include "../include/Utils.h"
#include "../include/IntegrityChunkWhitelist.h"
#include "../include/Config.h"
#include "../include/HashUtil.h"
#include "../include/HWID.h"
#include "../include/IntegrityTelemetry.h"
#include "../include/IntegrityHmacUtil.h"
#include "../include/RuntimeStats.h" // diperlukan untuk RuntimeStats::Instance().IncAwNtdll()
#include <windows.h>
#include <string>
#include <sstream>
#include <iomanip>
#include <fstream>

namespace OblivionEye {
namespace {
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

}

void NtdllIntegrity::HmacSha256(const unsigned char *key,size_t keyLen,const unsigned char *data,size_t dataLen,unsigned char out[32]) const {
    IntegrityHmacUtil::HmacSha256(key,keyLen,data,dataLen,out);
}

void NtdllIntegrity::BuildKey(std::vector<unsigned char> &key) const {
    IntegrityHmacUtil::BuildModuleKey(L"ntdll", key, true);
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
    for(size_t i=0;i<chunks;++i){ size_t off=i*chunk; size_t len=(off+chunk<=size)?chunk:(size-off); m_chunkHashes[i]=HashUtil::Sha256Trunc64(base+off,len);} return true;
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
    diskHash=HashUtil::Sha256Trunc64(textBase,textSize);
    const size_t chunk=OblivionEye::Config::CHUNK_SIZE; size_t chunks=(textSize+chunk-1)/chunk; diskChunks.resize(chunks);
    for(size_t i=0;i<chunks;++i){ size_t off=i*chunk; size_t len=(off+chunk<=textSize)?chunk:(textSize-off); diskChunks[i]=HashUtil::Sha256Trunc64(textBase+off,len); }
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
    if(!VerifyHmac()){ Log(L"NtdllIntegrity baseline HMAC mismatch, ignoring stored baseline"); m_chunkHashes.clear(); m_diskChunkHashes.clear(); m_hmacValid=false; IntegrityTelemetry::Instance().Ref(L"ntdll.dll").hmacMismatch++; return false; }
    m_baselineCaptured=true; m_diskCaptured=true; auto &st=IntegrityTelemetry::Instance().Ref(L"ntdll.dll"); st.baselineLoadsOk++; st.hmacValid=true; st.totalChunks=(uint32_t)m_chunkHashes.size(); st.whitelistedChunks=(uint32_t)IntegrityChunkWhitelist::CountFor(L"ntdll.dll"); st.chainDepth = st.chainDepth < 1 ? (m_prevChainValid?2:1) : st.chainDepth; return true;
}

void NtdllIntegrity::CaptureBaseline() {
    if (m_baselineCaptured)
        return;
    if (LoadBaseline()) {
        Log(L"NtdllIntegrity baseline loaded (persisted)");
        return;
    }

    unsigned char* base = nullptr; size_t size = 0;
    if (!GetNtdllTextRegion(base, size))
        return;

    m_baselineHash = HashUtil::Sha256Trunc64(base, size);
    CaptureSubsectionHashes();

    if (MapFreshDiskText(m_diskChunkHashes, m_diskHash))
        m_diskCaptured = true;

    ComputeHmac();
    SaveBaseline();
    m_baselineCaptured = true;
    Log(L"NtdllIntegrity baseline captured fresh");

    auto &st = IntegrityTelemetry::Instance().Ref(L"ntdll.dll");
    st.rebaselineCount++;
    st.baselineLoadsOk++;
    st.hmacValid = true;
    st.totalChunks = (uint32_t)m_chunkHashes.size();
    st.whitelistedChunks = (uint32_t)IntegrityChunkWhitelist::CountFor(L"ntdll.dll");
    st.lastBaselineTime = IntegrityTelemetry::Instance().NowIsoPublic();
}

bool NtdllIntegrity::ForceRebaseline(){
    unsigned char* base=nullptr; size_t size=0; if(!GetNtdllTextRegion(base,size)) return false; m_baselineHash=HashUtil::Sha256Trunc64(base,size); CaptureSubsectionHashes(); std::vector<unsigned long long> diskChunks; unsigned long long diskHash=0ULL; if(MapFreshDiskText(diskChunks,diskHash)){ m_diskChunkHashes=diskChunks; m_diskHash=diskHash; m_diskCaptured=true; }
    auto &st=IntegrityTelemetry::Instance().Ref(L"ntdll.dll"); if(OblivionEye::Config::INTEGRITY_CHAIN_BASELINE_DEFAULT && m_hmacValid){ m_prevChain=m_hmac; m_prevChainValid=true; st.chainAdvanceCount++; }
    ComputeHmac(); SaveBaseline(); m_baselineCaptured=true; st.rebaselineCount++; st.manualRebaselineCount++; st.baselineLoadsOk++; st.hmacValid=true; st.totalChunks=(uint32_t)m_chunkHashes.size(); st.whitelistedChunks=(uint32_t)IntegrityChunkWhitelist::CountFor(L"ntdll.dll"); auto nowIso=IntegrityTelemetry::Instance().NowIsoPublic(); st.lastManualRebaselineTime=nowIso; st.lastBaselineTime=nowIso; return true; }

bool NtdllIntegrity::VerifyNow(){ auto &st=IntegrityTelemetry::Instance().Ref(L"ntdll.dll"); st.verifyNowRequests++; unsigned char* base=nullptr; size_t size=0; if(!GetNtdllTextRegion(base,size)) return false; auto current=HashUtil::Sha256Trunc64(base,size); if(!m_baselineCaptured) return false; if(current!=m_baselineHash){ st.forceVerifyFailures++; return false; } return true; }

bool NtdllIntegrity::Check() {
    unsigned char* base=nullptr; size_t size=0; if(!GetNtdllTextRegion(base,size)) return false;
    // Consistent hashing: use truncated SHA256 (same as baseline capture)
    auto current = HashUtil::Sha256Trunc64(base, size);
    if(m_baselineCaptured && current!=m_baselineHash){
        const size_t chunk=OblivionEye::Config::CHUNK_SIZE; size_t chunks=(size+chunk-1)/chunk; std::wstring deltaInfo;
        bool allDiskMatches=true; std::vector<size_t> modifiedIdx;
        for(size_t i=0;i<chunks && i<m_chunkHashes.size(); ++i){
            size_t off=i*chunk; size_t len=(off+chunk<=size)?chunk:(size-off);
            unsigned long long h = HashUtil::Sha256Trunc64(base+off, len);
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
            for(auto idx: modifiedIdx){ size_t off=idx*chunk; size_t len=(off+chunk<=size)?chunk:(size-off); m_chunkHashes[idx]=HashUtil::Sha256Trunc64(base+off,len); }
            m_baselineHash=current; auto &st=IntegrityTelemetry::Instance().Ref(L"ntdll.dll"); if(OblivionEye::Config::INTEGRITY_CHAIN_BASELINE_DEFAULT && m_hmacValid){ m_prevChain = m_hmac; m_prevChainValid=true; st.chainAdvanceCount++; }
            ComputeHmac(); SaveBaseline(); st.rebaselineCount++; st.autoWhitelistCount++; st.lastAutoWhitelistTime = IntegrityTelemetry::Instance().NowIsoPublic(); st.lastBaselineTime=st.lastAutoWhitelistTime; st.whitelistedChunks=(uint32_t)IntegrityChunkWhitelist::CountFor(L"ntdll.dll"); RuntimeStats::Instance().IncAwNtdll(); Log(L"NtdllIntegrity auto-whitelisted disk-matching chunks: "+deltaInfo);
            return false; // suppressed detection
        }
        EventReporter::SendDetection(L"NtdllIntegrity", L"ntdll .text modified chunks:"+deltaInfo); ShowDetectionAndExit(L"ntdll integrity mismatch "+deltaInfo); return true;
    }
    return false;
}

NtdllIntegrity &NtdllIntegrity::Instance() { static NtdllIntegrity s; return s; }
void NtdllIntegrity::Tick() { if(!m_baselineCaptured) CaptureBaseline(); else Check(); }
}
