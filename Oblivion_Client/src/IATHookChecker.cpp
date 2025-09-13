#include "../pch.h"
#include "../include/IATHookChecker.h"
#include "../include/Logger.h"
#include "../include/EventReporter.h"
#include "../include/Utils.h"
#include <windows.h>
#include <psapi.h>

#pragma comment(lib, "psapi.lib")

namespace OblivionEye {

    IATHookChecker& IATHookChecker::Instance() { static IATHookChecker s; return s; }

    static bool IsAddressInsideModule(HMODULE mod, void* addr) {
        MODULEINFO mi{}; if (!GetModuleInformation(GetCurrentProcess(), mod, &mi, sizeof(mi))) return true;
        auto base = reinterpret_cast<uint8_t*>(mi.lpBaseOfDll); size_t size = (size_t)mi.SizeOfImage; auto p = (uint8_t*)addr; return p>=base && p<base+size;
    }

    bool IATHookChecker::ScanModuleIAT(HMODULE hMod) {
        uint8_t* base = (uint8_t*)hMod; auto dos=(PIMAGE_DOS_HEADER)base; if(dos->e_magic!=IMAGE_DOS_SIGNATURE) return false; auto nt=(PIMAGE_NT_HEADERS)(base+dos->e_lfanew); if(nt->Signature!=IMAGE_NT_SIGNATURE) return false; auto& dir=nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]; if(!dir.VirtualAddress) return false; auto impDesc=(PIMAGE_IMPORT_DESCRIPTOR)(base+dir.VirtualAddress);
        for(; impDesc->Name; ++impDesc){ auto oft=(PIMAGE_THUNK_DATA)(base+impDesc->OriginalFirstThunk); auto ft=(PIMAGE_THUNK_DATA)(base+impDesc->FirstThunk); if(!oft||!ft) continue; for(; oft->u1.AddressOfData; ++oft, ++ft){
#ifdef _WIN64
            if(!(oft->u1.Ordinal & IMAGE_ORDINAL_FLAG)){
                void* target=(void*)ft->u1.Function; HMODULE owner=nullptr; GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,(LPCWSTR)target,&owner);
                if(owner && !IsAddressInsideModule(owner,target)){ EventReporter::SendDetection(L"IATHookChecker", L"IAT hook"); ShowDetectionAndExit(L"IAT hook terdeteksi"); return true; }
            }
#else
            if(!(oft->u1.Ordinal & IMAGE_ORDINAL_FLAG32)){
                void* target=(void*)ft->u1.Function; HMODULE owner=nullptr; GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,(LPCSTR)target,&owner);
                if(owner && !IsAddressInsideModule(owner,target)){ EventReporter::SendDetection(L"IATHookChecker", L"IAT hook"); ShowDetectionAndExit(L"IAT hook terdeteksi"); return true; }
            }
#endif
        }}
        return false;
    }

    bool IATHookChecker::ScanIAT(){ HMODULE mods[1024]={}; DWORD needed=0; if(!EnumProcessModules(GetCurrentProcess(),mods,sizeof(mods),&needed)) return false; int count=needed/sizeof(HMODULE); for(int i=0;i<count;++i){ if(ScanModuleIAT(mods[i])) return true; } return false; }

    void IATHookChecker::Tick(){ ScanIAT(); }
}
