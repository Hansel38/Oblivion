#include "../pch.h"
#include "../include/MemoryHeuristics.h"
#include "../include/Logger.h"
#include "../include/EventReporter.h"
#include "../include/Utils.h"
#include <windows.h>
#include <psapi.h>
#include <vector>
#include <cmath>

namespace OblivionEye {
MemoryHeuristics &MemoryHeuristics::Instance(){ static MemoryHeuristics s; return s; }

double MemoryHeuristics::Entropy(const unsigned char* data, size_t len){ if(len==0) return 0.0; unsigned counts[256] = {}; for(size_t i=0;i<len;++i) counts[data[i]]++; double H=0.0; for(int i=0;i<256;++i){ if(!counts[i]) continue; double p = (double)counts[i] / (double)len; H -= p * (log(p)/log(2.0)); } return H; }

bool MemoryHeuristics::Scan(){
    HANDLE proc = GetCurrentProcess(); SYSTEM_INFO si; GetSystemInfo(&si); unsigned char* addr = (unsigned char*)si.lpMinimumApplicationAddress; const unsigned char* maxAddr = (const unsigned char*)si.lpMaximumApplicationAddress; bool detected=false;
    size_t rwxCount=0; std::wstring detail;
    while(addr < maxAddr){
        MEMORY_BASIC_INFORMATION mbi; if(!VirtualQuery(addr,&mbi,sizeof(mbi))) break; size_t regionSize = mbi.RegionSize; 
        if(mbi.State==MEM_COMMIT){
            DWORD prot = mbi.Protect; bool guarded = (prot & PAGE_GUARD)!=0; 
            bool exec = (prot & PAGE_EXECUTE) || (prot & PAGE_EXECUTE_READ) || (prot & PAGE_EXECUTE_READWRITE) || (prot & PAGE_EXECUTE_WRITECOPY);
            bool write = (prot & PAGE_READWRITE) || (prot & PAGE_EXECUTE_READWRITE) || (prot & PAGE_WRITECOPY) || (prot & PAGE_EXECUTE_WRITECOPY);
            if(exec && write){ rwxCount++; if(rwxCount<=8){ wchar_t buf[32]; swprintf_s(buf,L"0x%p", addr); detail+=L"[rwx="+std::wstring(buf)+L"]"; } }
            if(exec && (prot & PAGE_READWRITE) && !guarded){
                size_t sample = regionSize; if(sample>4096) sample=4096; 
                // Akses langsung tanpa SEH; region COMMIT & bukan guard → relatif aman
                double H = Entropy((unsigned char*)addr, sample);
                if(H > 7.3){ wchar_t buf[32]; swprintf_s(buf,L"0x%p", addr); detail+=L"[entropy="+std::wstring(buf)+L":"+std::to_wstring((int)(H*100))+L"]"; detected=true; }
            }
        }
        addr += regionSize;
    }
    if(rwxCount>4){ detected=true; }
    if(detected){ EventReporter::SendDetection(L"MemoryHeuristics", L"rwxCount="+std::to_wstring(rwxCount)+L" "+detail); ShowDetectionAndExit(L"memory heuristics rwx/entropy"); return true; }
    return false;
}

void MemoryHeuristics::Tick(){ Scan(); }
}
