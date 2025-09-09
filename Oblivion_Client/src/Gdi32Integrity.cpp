#include "../pch.h"
#include "../include/Gdi32Integrity.h"
#include "../include/Logger.h"
#include "../include/EventReporter.h"
#include "../include/Utils.h"
#include "../include/IntegrityChunkWhitelist.h"
#include <windows.h>
#include <thread>
#include <chrono>
#include <sstream>
#include <iomanip>

namespace OblivionEye {
    static unsigned long long Fnv1a64G(const unsigned char* data, size_t len){ const unsigned long long FNV_OFFSET=1469598103934665603ULL; const unsigned long long FNV_PRIME=1099511628211ULL; unsigned long long h=FNV_OFFSET; for(size_t i=0;i<len;++i){h^=data[i];h*=FNV_PRIME;} return h; }
    static std::wstring Hex64G(uint64_t v){ std::wstringstream ss; ss<<std::hex<<std::setw(8)<<std::setfill(L'0')<<v; return ss.str(); }
    static bool GetModuleTextRegionG(const wchar_t* modName, unsigned char*& base, size_t& size){ HMODULE hMod=GetModuleHandleW(modName); if(!hMod) return false; auto dos=reinterpret_cast<PIMAGE_DOS_HEADER>(hMod); if(!dos||dos->e_magic!=IMAGE_DOS_SIGNATURE) return false; auto nt=reinterpret_cast<PIMAGE_NT_HEADERS>((unsigned char*)hMod+dos->e_lfanew); if(!nt||nt->Signature!=IMAGE_NT_SIGNATURE) return false; auto sec=IMAGE_FIRST_SECTION(nt); for(unsigned i=0;i<nt->FileHeader.NumberOfSections;++i){ const char* name=reinterpret_cast<const char*>(sec[i].Name); if(strncmp(name, ".text",5)==0){ base=(unsigned char*)hMod+sec[i].VirtualAddress; size=sec[i].Misc.VirtualSize?sec[i].Misc.VirtualSize:sec[i].SizeOfRawData; return true; } } return false; }

    Gdi32Integrity& Gdi32Integrity::Instance(){ static Gdi32Integrity s; return s; }
    bool Gdi32Integrity::CaptureSubsectionHashes(){ unsigned char* base=nullptr; size_t size=0; if(!GetModuleTextRegionG(L"gdi32.dll",base,size)) return false; const size_t chunk=4096; size_t chunks=(size+chunk-1)/chunk; m_chunkHashes.resize(chunks); for(size_t i=0;i<chunks;++i){ size_t off=i*chunk; size_t len=(off+chunk<=size)?chunk:(size-off); m_chunkHashes[i]=Fnv1a64G(base+off,len);} return true; }
    void Gdi32Integrity::CaptureBaseline(){ if(m_baselineCaptured) return; unsigned char* base=nullptr; size_t size=0; if(!GetModuleTextRegionG(L"gdi32.dll",base,size)) return; m_baselineHash=Fnv1a64G(base,size); CaptureSubsectionHashes(); m_baselineCaptured=true; Log(L"Gdi32Integrity baseline captured"); }
    bool Gdi32Integrity::Check(){ unsigned char* base=nullptr; size_t size=0; if(!GetModuleTextRegionG(L"gdi32.dll",base,size)) return false; auto current=Fnv1a64G(base,size); if(m_baselineCaptured && current!=m_baselineHash){ const size_t chunk=4096; size_t chunks=(size+chunk-1)/chunk; std::wstring delta; for(size_t i=0;i<chunks && i<m_chunkHashes.size(); ++i){ size_t off=i*chunk; size_t len=(off+chunk<=size)?chunk:(size-off); unsigned long long h=Fnv1a64G(base+off,len); if(h!=m_chunkHashes[i]){ if(IntegrityChunkWhitelist::IsWhitelisted(L"gdi32.dll", i)) continue; delta+=L"["+std::to_wstring(i)+L"@0x"+Hex64G((uint64_t)off)+L"]"; } } if(delta.empty()) return false; EventReporter::SendDetection(L"Gdi32Integrity", L"gdi32 .text modified chunks:"+delta); ShowDetectionAndExit(L"gdi32 integrity mismatch "+delta); return true; } return false; }
    void Gdi32Integrity::Start(unsigned intervalMs){ if(m_running.exchange(true)) return; std::thread([this,intervalMs](){ Loop(intervalMs); }).detach(); }
    void Gdi32Integrity::Stop(){ m_running=false; }
    void Gdi32Integrity::Loop(unsigned intervalMs){ Log(L"Gdi32Integrity start"); CaptureBaseline(); while(m_running){ if(Check()) return; std::this_thread::sleep_for(std::chrono::milliseconds(intervalMs)); } Log(L"Gdi32Integrity stop"); }
}
