#include "../pch.h"
#include "../include/HandleProtection.h"
#include "../include/Logger.h"
#include <windows.h>
#include <sddl.h>
#include <AccCtrl.h>
#include <Aclapi.h>
#pragma comment(lib, "advapi32.lib")

namespace OblivionEye {

    static void DropSeDebugPrivilege() {
        HANDLE hToken = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) return;
        LUID luid;
        if (!LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &luid)) { if (hToken) CloseHandle(hToken); return; }
        TOKEN_PRIVILEGES tp{}; tp.PrivilegeCount = 1; tp.Privileges[0].Luid = luid; tp.Privileges[0].Attributes = 0; // disable
        AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr);
        CloseHandle(hToken);
    }

    static void HardenProcessDacl() {
        // Buat DACL ketat: hanya SYSTEM dan owner yang punya akses penuh
        PSECURITY_DESCRIPTOR pSD = nullptr; PACL pDACL = nullptr;
        PSID pSystemSID = nullptr; PSID pOwnerSID = nullptr;
        SID_IDENTIFIER_AUTHORITY NtAuth = SECURITY_NT_AUTHORITY;
        if (!AllocateAndInitializeSid(&NtAuth, 1, SECURITY_LOCAL_SYSTEM_RID,0,0,0,0,0,0,0, &pSystemSID)) {
            return;
        }

        HANDLE hToken = nullptr; OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken);
        DWORD len = 0; GetTokenInformation(hToken, TokenOwner, nullptr, 0, &len);
        PTOKEN_OWNER owner = (PTOKEN_OWNER)LocalAlloc(LMEM_FIXED, len);
        if (hToken && owner && GetTokenInformation(hToken, TokenOwner, owner, len, &len)) {
            pOwnerSID = owner->Owner;
        }

        EXPLICIT_ACCESSW ea[2] = {};
        ea[0].grfAccessPermissions = GENERIC_ALL; ea[0].grfAccessMode = SET_ACCESS; ea[0].grfInheritance=NO_INHERITANCE; ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID; ea[0].Trustee.TrusteeType = TRUSTEE_IS_USER; ea[0].Trustee.ptstrName = (LPWSTR)pSystemSID;
        ea[1].grfAccessPermissions = GENERIC_ALL; ea[1].grfAccessMode = SET_ACCESS; ea[1].grfInheritance=NO_INHERITANCE; ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID; ea[1].Trustee.TrusteeType = TRUSTEE_IS_USER; ea[1].Trustee.ptstrName = (LPWSTR)pOwnerSID;

        SetEntriesInAclW(2, ea, nullptr, &pDACL);
        pSD = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);
        InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION);
        SetSecurityDescriptorDacl(pSD, TRUE, pDACL, FALSE);

        SetKernelObjectSecurity(GetCurrentProcess(), DACL_SECURITY_INFORMATION, pSD);

        if (hToken) CloseHandle(hToken);
        if (owner) LocalFree(owner);
        if (pDACL) LocalFree(pDACL);
        if (pSD) LocalFree(pSD);
        if (pSystemSID) FreeSid(pSystemSID);
    }

    static void EnableMitigations() {
        // Placeholder: mitigasi tambahan bisa ditambahkan di versi lanjutan
    }

    void HandleProtection::Apply() {
        DropSeDebugPrivilege();
        HardenProcessDacl();
        EnableMitigations();
        Log(L"HandleProtection applied");
    }
}
