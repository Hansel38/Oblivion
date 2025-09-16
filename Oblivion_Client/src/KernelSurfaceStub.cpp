#include "../pch.h"
#include "../include/KernelSurfaceStub.h"
#include "../include/Logger.h"
#include "../include/HashUtil.h"
#include "../include/EventReporter.h"
#include "../include/Utils.h"
#include <windows.h>
#include <psapi.h>
#include <winternl.h> // untuk akses struktur PEB; jika tidak tersedia definisikan minimal fallback di bawah

#ifndef _WINTERNL_ // fallback minimal jika winternl tidak menyediakan definisi (hindari gagal kompilasi PPEB)
typedef struct _PEB_LDR_DATA *PPEB_LDR_DATA;
typedef struct _RTL_USER_PROCESS_PARAMETERS *PRTL_USER_PROCESS_PARAMETERS;
typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PPEB_LDR_DATA Ldr;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
} PEB, *PPEB;
#endif

namespace OblivionEye {
namespace {
    uint64_t HashSnapshot(uint32_t modCount, void* peb, void* ldr, void* procParams) {
        unsigned char buf[sizeof(uint32_t)+sizeof(void*)*3];
        memcpy(buf, &modCount, sizeof(uint32_t));
        memcpy(buf+sizeof(uint32_t), &peb, sizeof(void*));
        memcpy(buf+sizeof(uint32_t)+sizeof(void*), &ldr, sizeof(void*));
        memcpy(buf+sizeof(uint32_t)+sizeof(void*)*2, &procParams, sizeof(void*));
        return HashUtil::Sha256Trunc64(buf, sizeof(buf));
    }
}

KernelSurfaceStub &KernelSurfaceStub::Instance(){ static KernelSurfaceStub s; return s; }

void KernelSurfaceStub::CaptureBaseline(){
#ifdef _WIN64
    PPEB peb = (PPEB)__readgsqword(0x60);
#else
    PPEB peb = (PPEB)__readfsdword(0x30);
#endif
    HMODULE mods[256]; DWORD needed=0; uint32_t count=0; if(EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &needed)){ count = needed/sizeof(HMODULE); }
    void* ldr = nullptr; void* params=nullptr; if(peb){ ldr = peb->Ldr; params = peb->ProcessParameters; }
    m_modCount = count; m_pebHash = HashSnapshot(count, peb, ldr, params); m_baselineCaptured=true; Log(L"KernelSurfaceStub baseline captured");
}

bool KernelSurfaceStub::Check(){
    if(!m_baselineCaptured) return false;
#ifdef _WIN64
    PPEB peb = (PPEB)__readgsqword(0x60);
#else
    PPEB peb = (PPEB)__readfsdword(0x30);
#endif
    HMODULE mods[256]; DWORD needed=0; uint32_t count=0; if(EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &needed)){ count = needed/sizeof(HMODULE); }
    void* ldr = nullptr; void* params=nullptr; if(peb){ ldr = peb->Ldr; params = peb->ProcessParameters; }
    auto h = HashSnapshot(count, peb, ldr, params);
    if(count != m_modCount || h != m_pebHash){
        EventReporter::SendDetection(L"KernelSurfaceStub", L"kernel surface drift modCount="+std::to_wstring(count)+L" baseline="+std::to_wstring(m_modCount));
        ShowDetectionAndExit(L"kernel surface drift");
        return true;
    }
    return false;
}

void KernelSurfaceStub::Tick(){ if(!m_baselineCaptured) CaptureBaseline(); else Check(); }
}
