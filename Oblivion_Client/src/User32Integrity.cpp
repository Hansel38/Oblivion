#include "../pch.h"
#include "../include/User32Integrity.h"
#include "../include/Logger.h"
#include "../include/EventReporter.h"
#include "../include/Utils.h"
#include "../include/IntegrityChunkWhitelist.h"
#include <windows.h>
#include <sstream>
#include <iomanip>

namespace OblivionEye {
    static unsigned long long Fnv1a64U(const unsigned char* d,size_t l){ const unsigned long long O=1469598103934665603ULL; const unsigned long long P=1099511628211ULL; unsigned long long h=O; for(size_t i=0;i<l;++i){ h^=d[i]; h*=P;} return h; }
    static std::wstring Hex64U(uint64_t v){ std::wstringstream ss; ss<<std::hex<<std::setw(8)<<std::setfill(L'0')<<v; return ss.str(); }
    static bool GetModuleTextRegionU(const wchar_t* mod,unsigned char*& b,size_t& s){ HMODULE h=GetModuleHandleW(mod); if(!h) return false; auto dos=(PIMAGE_DOS_HEADER)h; if(!dos||dos->e_magic!=IMAGE_DOS_SIGNATURE) return false; auto nt=(PIMAGE_NT_HEADERS)((unsigned char*)h+dos->e_lfanew); if(!nt||nt->Signature!=IMAGE_NT_SIGNATURE) return false; auto sec=IMAGE_FIRST_SECTION(nt); for(unsigned i=0;i<nt->FileHeader.NumberOfSections;++i){ const char* name=(const char*)sec[i].Name; if(strncmp(name, ".text",5)==0){ b=(unsigned char*)h+sec[i].VirtualAddress; s=sec[i].Misc.VirtualSize?sec[i].Misc.VirtualSize:sec[i].SizeOfRawData; return true; } } return false; }
    User32Integrity& User32Integrity::Instance(){ static User32Integrity s; return s; }
    bool User32Integrity::CaptureSubsectionHashes(){ unsigned char* base=nullptr; size_t size=0; if(!GetModuleTextRegionU(L"user32.dll",base,size)) return false; const size_t C=4096; size_t n=(size+C-1)/C; m_chunkHashes.resize(n); for(size_t i=0;i<n;++i){ size_t off=i*C; size_t len=(off+C<=size)?C:(size-off); m_chunkHashes[i]=Fnv1a64U(base+off,len);} return true; }
    void User32Integrity::CaptureBaseline(){ if(m_baselineCaptured) return; unsigned char* base=nullptr; size_t size=0; if(!GetModuleTextRegionU(L"user32.dll",base,size)) return; m_baselineHash=Fnv1a64U(base,size); CaptureSubsectionHashes(); m_baselineCaptured=true; Log(L"User32Integrity baseline captured"); }
    bool User32Integrity::Check(){ unsigned char* base=nullptr; size_t size=0; if(!GetModuleTextRegionU(L"user32.dll",base,size)) return false; auto current=Fnv1a64U(base,size); if(m_baselineCaptured && current!=m_baselineHash){ const size_t C=4096; size_t n=(size+C-1)/C; std::wstring delta; for(size_t i=0;i<n && i<m_chunkHashes.size(); ++i){ size_t off=i*C; size_t len=(off+C<=size)?C:(size-off); unsigned long long h=Fnv1a64U(base+off,len); if(h!=m_chunkHashes[i]){ if(IntegrityChunkWhitelist::IsWhitelisted(L"user32.dll", i)) continue; delta+=L"["+std::to_wstring(i)+L"@0x"+Hex64U((uint64_t)off)+L"]"; } } if(delta.empty()) return false; EventReporter::SendDetection(L"User32Integrity", L"user32 .text modified chunks:"+delta); ShowDetectionAndExit(L"user32 integrity mismatch "+delta); return true; } return false; }
    void User32Integrity::Tick(){ if(!m_baselineCaptured) CaptureBaseline(); else Check(); }
}
