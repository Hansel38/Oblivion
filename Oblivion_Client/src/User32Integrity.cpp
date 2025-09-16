#include "../pch.h"
#include "../include/User32Integrity.h"
#include "../include/Logger.h"
#include "../include/EventReporter.h"
#include "../include/Utils.h"
#include "../include/IntegrityChunkWhitelist.h"
#include "../include/HashUtil.h"
#include "../include/Config.h"
#include <windows.h>
#include <sstream>
#include <iomanip>

namespace OblivionEye {
namespace {
    inline unsigned long long Hash64(const unsigned char *d, size_t l) {
        return OblivionEye::HashUtil::Sha256Trunc64(d, l);
    }

    std::wstring Hex64(uint64_t v) {
        std::wstringstream ss; ss << std::hex << std::setw(8) << std::setfill(L'0') << v; return ss.str();
    }

    bool GetModuleTextRegion(const wchar_t *mod, unsigned char *&b, size_t &s) {
        HMODULE h = GetModuleHandleW(mod); if (!h) return false;
        auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(h); if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
        auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<unsigned char*>(h) + dos->e_lfanew); if (!nt || nt->Signature != IMAGE_NT_SIGNATURE) return false;
        auto sec = IMAGE_FIRST_SECTION(nt);
        for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
            const char *name = reinterpret_cast<const char*>(sec[i].Name);
            if (strncmp(name, ".text", 5) == 0) {
                b = reinterpret_cast<unsigned char*>(h) + sec[i].VirtualAddress;
                s = sec[i].Misc.VirtualSize ? sec[i].Misc.VirtualSize : sec[i].SizeOfRawData;
                return true;
            }
        }
        return false;
    }
}

User32Integrity &User32Integrity::Instance() { static User32Integrity s; return s; }

bool User32Integrity::CaptureSubsectionHashes() {
    unsigned char *base = nullptr; size_t size = 0;
    if (!GetModuleTextRegion(L"user32.dll", base, size)) return false;
    const size_t chunk = OblivionEye::Config::CHUNK_SIZE; size_t n = (size + chunk - 1) / chunk;
    m_chunkHashes.resize(n);
    for (size_t i = 0; i < n; ++i) {
        size_t off = i * chunk; size_t len = (off + chunk <= size) ? chunk : (size - off);
        m_chunkHashes[i] = Hash64(base + off, len);
    }
    return true;
}

void User32Integrity::CaptureBaseline() {
    if (m_baselineCaptured) return;
    unsigned char *base = nullptr; size_t size = 0;
    if (!GetModuleTextRegion(L"user32.dll", base, size)) return;
    m_baselineHash = Hash64(base, size);
    CaptureSubsectionHashes();
    // Capture disk copy for delta annotation
    wchar_t sysDir[MAX_PATH]; if(GetSystemDirectoryW(sysDir, MAX_PATH)) {
        std::wstring path = std::wstring(sysDir) + L"\\user32.dll"; HANDLE f=CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,0,nullptr); if(f!=INVALID_HANDLE_VALUE){ HANDLE map=CreateFileMappingW(f,nullptr,PAGE_READONLY,0,0,nullptr); if(map){ void* view=MapViewOfFile(map,FILE_MAP_READ,0,0,0); if(view){ unsigned char* b=(unsigned char*)view; auto dos=(PIMAGE_DOS_HEADER)b; if(dos->e_magic==IMAGE_DOS_SIGNATURE){ auto nt=(PIMAGE_NT_HEADERS)(b+dos->e_lfanew); auto sec=IMAGE_FIRST_SECTION(nt); unsigned char* tBase=nullptr; size_t tSize=0; for(unsigned i=0;i<nt->FileHeader.NumberOfSections;++i){ if(strncmp((const char*)sec[i].Name, ".text",5)==0){ tBase=b+sec[i].VirtualAddress; tSize=sec[i].Misc.VirtualSize?sec[i].Misc.VirtualSize:sec[i].SizeOfRawData; break; } } if(tBase && tSize){ m_diskHash=Hash64(tBase,tSize); const size_t chunk = OblivionEye::Config::CHUNK_SIZE; size_t n=(tSize+chunk-1)/chunk; m_diskChunkHashes.resize(n); for(size_t i=0;i<n;++i){ size_t off=i*chunk; size_t len=(off+chunk<=tSize)?chunk:(tSize-off); m_diskChunkHashes[i]=Hash64(tBase+off,len);} m_diskCaptured=true; } }
                    UnmapViewOfFile(view); }
                CloseHandle(map); }
            CloseHandle(f); }
    }
    m_baselineCaptured = true;
    Log(L"User32Integrity baseline captured");
}

bool User32Integrity::Check() {
    unsigned char *base = nullptr; size_t size = 0;
    if (!GetModuleTextRegion(L"user32.dll", base, size)) return false;
    auto current = Hash64(base, size);

    if (!m_baselineCaptured || current == m_baselineHash)
        return false;

    const size_t chunk = OblivionEye::Config::CHUNK_SIZE; size_t n = (size + chunk - 1) / chunk;
    std::wstring delta;
    std::vector<size_t> modifiedIdx; bool allDiskMatches=true;
    for (size_t i = 0; i < n && i < m_chunkHashes.size(); ++i) {
        size_t off = i * chunk;
        size_t len = (off + chunk <= size) ? chunk : (size - off);
        unsigned long long h = Hash64(base + off, len);
        if (h != m_chunkHashes[i]) {
            if (IntegrityChunkWhitelist::IsWhitelisted(L"user32.dll", i))
                continue;
            modifiedIdx.push_back(i);
            delta += L"[m" + std::to_wstring(i) + L"@0x" + Hex64(static_cast<uint64_t>(off)) + L"]";
            if(m_diskCaptured && i < m_diskChunkHashes.size()) {
                if(m_diskChunkHashes[i]==h) delta += L"(=disk)"; else { delta += L"(!disk)"; allDiskMatches=false; }
            } else allDiskMatches=false;
        }
    }

    if (delta.empty())
        return false;

    if(OblivionEye::Config::INTEGRITY_AUTO_WHITELIST_DISK_MATCH_DEFAULT && !modifiedIdx.empty() && allDiskMatches){
        for(auto idx: modifiedIdx) IntegrityChunkWhitelist::Add(L"user32.dll", idx);
        for(auto idx: modifiedIdx){ size_t off=idx*chunk; size_t len=(off+chunk<=size)?chunk:(size-off); m_chunkHashes[idx]=Hash64(base+off,len); }
        m_baselineHash = current; Log(L"User32Integrity auto-whitelisted disk-matching chunks: "+delta); return false;
    }

    EventReporter::SendDetection(L"User32Integrity", L"user32 .text modified chunks:" + delta);
    ShowDetectionAndExit(L"user32 integrity mismatch " + delta);
    return true;
}

void User32Integrity::Tick() { if (!m_baselineCaptured) CaptureBaseline(); else Check(); }
}
