#include "../pch.h"
#include "../include/DigitalSignature.h"
#include <windows.h>
#include <wincrypt.h>
#include <softpub.h>
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

namespace OblivionEye {

    bool VerifyFileIsSigned(const std::wstring& path) {
        WINTRUST_FILE_INFO fileInfo{};
        fileInfo.cbStruct = sizeof(fileInfo);
        fileInfo.pcwszFilePath = path.c_str();
        fileInfo.hFile = nullptr;
        fileInfo.pgKnownSubject = nullptr;

        GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

        WINTRUST_DATA wintrustData{};
        wintrustData.cbStruct = sizeof(wintrustData);
        wintrustData.pPolicyCallbackData = nullptr;
        wintrustData.pSIPClientData = nullptr;
        wintrustData.dwUIChoice = WTD_UI_NONE;
        wintrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
        wintrustData.dwUnionChoice = WTD_CHOICE_FILE;
        wintrustData.dwStateAction = WTD_STATEACTION_IGNORE;
        wintrustData.pFile = &fileInfo;
        wintrustData.dwProvFlags = WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL;

        LONG status = WinVerifyTrust(nullptr, &policyGUID, &wintrustData);
        return status == ERROR_SUCCESS;
    }
}
