#include "../pch.h"
#include "../include/HandleProtection.h"
#include "../include/Logger.h"
#include <windows.h>
#include <sddl.h>
#include <AccCtrl.h>
#include <Aclapi.h>

#pragma comment(lib, "advapi32.lib")

namespace OblivionEye {
namespace {
    void DropSeDebugPrivilege() {
        HANDLE hToken = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
            return;
        LUID luid{};
        if (LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &luid)) {
            TOKEN_PRIVILEGES tp{};
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = 0; // disable
            AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr);
        }
        CloseHandle(hToken);
    }

    void HardenProcessDacl() {
        // Restrict DACL to SYSTEM and owner
        PSID pSystemSID = nullptr;
        SID_IDENTIFIER_AUTHORITY NtAuth = SECURITY_NT_AUTHORITY;
        if (!AllocateAndInitializeSid(&NtAuth, 1, SECURITY_LOCAL_SYSTEM_RID,
                                      0, 0, 0, 0, 0, 0, 0, &pSystemSID))
            return;

        HANDLE hToken = nullptr;
        PTOKEN_OWNER owner = nullptr;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
            DWORD len = 0;
            GetTokenInformation(hToken, TokenOwner, nullptr, 0, &len);
            owner = static_cast<PTOKEN_OWNER>(LocalAlloc(LMEM_FIXED, len));
            if (!owner || !GetTokenInformation(hToken, TokenOwner, owner, len, &len)) {
                if (owner) LocalFree(owner);
                owner = nullptr;
            }
        }
        PSID pOwnerSID = owner ? owner->Owner : nullptr;

        EXPLICIT_ACCESSW ea[2] = {};
        ea[0].grfAccessPermissions = GENERIC_ALL;
        ea[0].grfAccessMode = SET_ACCESS;
        ea[0].grfInheritance = NO_INHERITANCE;
        ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
        ea[0].Trustee.TrusteeType = TRUSTEE_IS_USER;
        ea[0].Trustee.ptstrName = (LPWSTR)pSystemSID;

        ea[1] = ea[0];
        ea[1].Trustee.ptstrName = (LPWSTR)pOwnerSID;

        PACL pDACL = nullptr;
        if (SetEntriesInAclW(2, ea, nullptr, &pDACL) == ERROR_SUCCESS) {
            PSECURITY_DESCRIPTOR pSD = LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);
            if (pSD) {
                if (InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION)) {
                    if (SetSecurityDescriptorDacl(pSD, TRUE, pDACL, FALSE)) {
                        SetKernelObjectSecurity(GetCurrentProcess(), DACL_SECURITY_INFORMATION, pSD);
                    }
                }
                LocalFree(pSD);
            }
        }

        if (hToken) CloseHandle(hToken);
        if (owner) LocalFree(owner);
        if (pDACL) LocalFree(pDACL);
        if (pSystemSID) FreeSid(pSystemSID);
    }

    void EnableMitigations() {
        // Placeholder for future mitigations
    }
}

void HandleProtection::Apply() {
    DropSeDebugPrivilege();
    HardenProcessDacl();
    EnableMitigations();
    Log(L"HandleProtection applied");
}
}
