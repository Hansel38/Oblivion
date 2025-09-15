#include "../pch.h"
#include "../include/HandleProtection.h"
#include "../include/Logger.h"
#include <windows.h>
#include <sddl.h>
#include <AccCtrl.h>
#include <Aclapi.h>
#include <vector>
#include <unordered_set>
// Clean rewritten HandleProtection with stable handle enumeration
#include "../pch.h"
#include "../include/HandleProtection.h"
#include "../include/Logger.h"
#include "../include/Config.h"
#include "../include/DetectionCorrelator.h"
#include <windows.h>
#include <sddl.h>
#include <AccCtrl.h>
#include <Aclapi.h>
#include <vector>
#include <unordered_set>

// Minimal NT declarations
typedef long NTSTATUS;
typedef NTSTATUS (NTAPI *PFN_NtQuerySystemInformation)(int,PVOID,ULONG,PULONG);
static const int kSystemHandleInformation = 16;

struct SYS_HANDLE_COMPAT { // compact layout for 32-bit/64-bit typical
    USHORT  pid;
    USHORT  creatorBacktrace;
    UCHAR   objType;
    UCHAR   flags;
    USHORT  handle;
    PVOID   object;
    ULONG   access;
};
struct SYS_HANDLE_INFO_COMPAT {
    ULONG count;
    SYS_HANDLE_COMPAT handles[1];
};

namespace OblivionEye {
namespace {
    void DropSeDebugPrivilege(){ HANDLE hToken=nullptr; if(!OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,&hToken)) return; LUID luid{}; if(LookupPrivilegeValueW(nullptr,SE_DEBUG_NAME,&luid)){ TOKEN_PRIVILEGES tp{}; tp.PrivilegeCount=1; tp.Privileges[0].Luid=luid; tp.Privileges[0].Attributes=0; AdjustTokenPrivileges(hToken,FALSE,&tp,sizeof(tp),nullptr,nullptr);} if(hToken) CloseHandle(hToken);}    
    void HardenProcessDacl(){ PSID sysSid=nullptr; SID_IDENTIFIER_AUTHORITY NtAuth=SECURITY_NT_AUTHORITY; if(!AllocateAndInitializeSid(&NtAuth,1,SECURITY_LOCAL_SYSTEM_RID,0,0,0,0,0,0,0,&sysSid)) return; HANDLE hTok=nullptr; PTOKEN_OWNER owner=nullptr; if(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&hTok)){ DWORD len=0; GetTokenInformation(hTok,TokenOwner,nullptr,0,&len); owner=(PTOKEN_OWNER)LocalAlloc(LMEM_FIXED,len); if(!owner||!GetTokenInformation(hTok,TokenOwner,owner,len,&len)){ if(owner) LocalFree(owner); owner=nullptr; }} PSID ownerSid= owner? owner->Owner: nullptr; EXPLICIT_ACCESSW ea[2]{}; for(int i=0;i<2;i++){ ea[i].grfAccessPermissions=GENERIC_ALL; ea[i].grfAccessMode=SET_ACCESS; ea[i].grfInheritance=NO_INHERITANCE; ea[i].Trustee.TrusteeForm=TRUSTEE_IS_SID; ea[i].Trustee.TrusteeType=TRUSTEE_IS_USER;} ea[0].Trustee.ptstrName=(LPWSTR)sysSid; ea[1].Trustee.ptstrName=(LPWSTR)ownerSid; PACL dacl=nullptr; if(SetEntriesInAclW(2,ea,nullptr,&dacl)==ERROR_SUCCESS){ PSECURITY_DESCRIPTOR sd=LocalAlloc(LPTR,SECURITY_DESCRIPTOR_MIN_LENGTH); if(sd){ if(InitializeSecurityDescriptor(sd,SECURITY_DESCRIPTOR_REVISION) && SetSecurityDescriptorDacl(sd,TRUE,dacl,FALSE)) SetKernelObjectSecurity(GetCurrentProcess(),DACL_SECURITY_INFORMATION,sd); LocalFree(sd);} } if(hTok) CloseHandle(hTok); if(owner) LocalFree(owner); if(dacl) LocalFree(dacl); if(sysSid) FreeSid(sysSid);}    
}

static DWORD g_lastScanTick=0;
static std::unordered_set<DWORD> g_seenPids;

void HandleProtection::Apply(){ DropSeDebugPrivilege(); HardenProcessDacl(); Log(L"HandleProtection applied"); }

bool HandleProtection::ScanOnce(){ DWORD now=GetTickCount(); if(now - g_lastScanTick < Config::HANDLE_SCAN_COOLDOWN_MS) return false; g_lastScanTick = now; HMODULE hNt=GetModuleHandleW(L"ntdll.dll"); if(!hNt) return false; auto NtQuerySystemInformation=(PFN_NtQuerySystemInformation)GetProcAddress(hNt,"NtQuerySystemInformation"); if(!NtQuerySystemInformation) return false; ULONG sz=0x10000; NTSTATUS st; std::vector<BYTE> buf; for(int r=0;r<6;r++){ buf.resize(sz); st=NtQuerySystemInformation(kSystemHandleInformation,buf.data(),sz,&sz); if(st==0) break; if(st==0xC0000004L){ sz*=2; continue;} return false;} if(st!=0) return false; auto *info=reinterpret_cast<SYS_HANDLE_INFO_COMPAT*>(buf.data()); if(!info) return false; DWORD self=GetCurrentProcessId(); g_seenPids.clear(); size_t reported=0; const ULONG WRITE_MASK= 0x0001|0x0002|0x0008|0x0020|0x0040|0x0800; // terminate|create_thread|vm_op|vm_write|dup|suspend
    for(ULONG i=0;i<info->count;i++){ const auto &h=info->handles[i]; if(h.pid==self) continue; if((h.access & WRITE_MASK)==0) continue; if(g_seenPids.count(h.pid)) continue; if(reported < Config::HANDLE_SCAN_MAX_DUP){ wchar_t acc[16]; swprintf(acc,16,L"%08X", (unsigned)h.access); Log(L"DETECTION|HandleProtection|ExternalHandle pid="+std::to_wstring(h.pid)+L" access=0x"+acc); DetectionCorrelator::Instance().Report(L"EXT_HANDLE", L"pid="+std::to_wstring(h.pid), Config::EXT_HANDLE_SCORE, true); g_seenPids.insert(h.pid); ++reported; } else if (reported==Config::HANDLE_SCAN_MAX_DUP){ Log(L"INFO|HandleProtection|ExternalHandle more_truncated"); ++reported; }
    }
    return reported>0;
}

void HandleProtection::Tick(){ ScanOnce(); }
}

