#include "../pch.h"
#include "../include/Kernel32Integrity.h"
#include "../include/Logger.h"
#include "../include/EventReporter.h"
#include "../include/Utils.h"
#include "../include/IntegrityChunkWhitelist.h"
#include <windows.h>
#include <string>
#include <sstream>
#include <iomanip>

namespace OblivionEye {
    static unsigned long long Fnv1a64(const unsigned char* data,size_t len){ const unsigned long long FNV_OFFSET=1469598103934665603ULL; const unsigned long long FNV_PRIME=1099511628211ULL; unsigned long long h=FNV_OFFSET; for(size_t i=0;i<len;++i){h^=data[i]; h*=FNV_PRIME;} return h; }
    static std::wstring Hex64(uint64_t v){ std::wstringstream ss; ss<<std::hex<<std::setw(8)<<std::setfill(L'0')<<v; return ss.str(); }
    static bool GetModuleTextRegion(HMODULE hMod,unsigned char*& base,size_t& size){ if(!hMod) return false; auto dos=(PIMAGE_DOS_HEADER)hMod; if(!dos||dos->e_magic!=IMAGE_DOS_SIGNATURE) return false; auto nt=(PIMAGE_NT_HEADERS)((unsigned char*)hMod+dos->e_lfanew); if(!nt||nt->Signature!=IMAGE_NT_SIGNATURE) return false; auto sec=IMAGE_FIRST_SECTION(nt); for(unsigned i=0;i<nt->FileHeader.NumberOfSections;++i){ const char* name=(const char*)sec[i].Name; if(strncmp(name, ".text",5)==0){ base=(unsigned char*)hMod+sec[i].VirtualAddress; size=sec[i].Misc.VirtualSize?sec[i].Misc.VirtualSize:sec[i].SizeOfRawData; return true; } } return false; }
    Kernel32Integrity& Kernel32Integrity::Instance(){ static Kernel32Integrity s; return s; }
    bool Kernel32Integrity::CaptureSubsectionHashes(){ unsigned char* base=nullptr; size_t size=0; if(!GetModuleTextRegion(GetModuleHandleW(L"kernel32.dll"),base,size)) return false; const size_t chunk=4096; size_t chunks=(size+chunk-1)/chunk; m_chunkHashes.resize(chunks); for(size_t i=0;i<chunks;++i){ size_t off=i*chunk; size_t len=(off+chunk<=size)?chunk:(size-off); m_chunkHashes[i]=Fnv1a64(base+off,len);} return true; }
    void Kernel32Integrity::CaptureBaseline(){ if(m_baselineCaptured) return; unsigned char* base=nullptr; size_t size=0; if(!GetModuleTextRegion(GetModuleHandleW(L"kernel32.dll"),base,size)) return; m_baselineHash=Fnv1a64(base,size); CaptureSubsectionHashes(); m_baselineCaptured=true; Log(L"Kernel32Integrity baseline captured"); }
    bool Kernel32Integrity::Check(){ unsigned char* base=nullptr; size_t size=0; if(!GetModuleTextRegion(GetModuleHandleW(L"kernel32.dll"),base,size)) return false; auto current=Fnv1a64(base,size); if(m_baselineCaptured && current!=m_baselineHash){ const size_t chunk=4096; size_t chunks=(size+chunk-1)/chunk; std::wstring deltaInfo; for(size_t i=0;i<chunks && i<m_chunkHashes.size(); ++i){ size_t off=i*chunk; size_t len=(off+chunk<=size)?chunk:(size-off); unsigned long long h=Fnv1a64(base+off,len); if(h!=m_chunkHashes[i]){ if(IntegrityChunkWhitelist::IsWhitelisted(L"kernel32.dll", i)) continue; deltaInfo+=L"["+std::to_wstring(i)+L"@0x"+Hex64((uint64_t)off)+L"]"; } } if(deltaInfo.empty()) return false; EventReporter::SendDetection(L"Kernel32Integrity", L"kernel32 .text modified chunks:"+deltaInfo); ShowDetectionAndExit(L"kernel32 integrity mismatch "+deltaInfo); return true; } return false; }
    void Kernel32Integrity::Tick(){ if(!m_baselineCaptured) CaptureBaseline(); else Check(); }
}
