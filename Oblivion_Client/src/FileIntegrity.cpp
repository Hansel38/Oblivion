#include "../pch.h"
#include "../include/FileIntegrity.h"
#include <windows.h>
#include <wincrypt.h>
#include <string>

#pragma comment(lib, "advapi32.lib")

namespace OblivionEye {
namespace {
    struct HandleCloser { HANDLE h; ~HandleCloser(){ if(h && h!=INVALID_HANDLE_VALUE) CloseHandle(h); } };
    struct CryptReleaser { HCRYPTHASH hHash=0; HCRYPTPROV hProv=0; ~CryptReleaser(){ if(hHash) CryptDestroyHash(hHash); if(hProv) CryptReleaseContext(hProv,0); } };
}

std::wstring MD5OfFile(const std::wstring &path) {
    HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE)
        return {};
    HandleCloser file{hFile};

    CryptReleaser cr;
    if (!CryptAcquireContextW(&cr.hProv, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
        return {};
    if (!CryptCreateHash(cr.hProv, CALG_MD5, 0, 0, &cr.hHash))
        return {};

    BYTE buffer[4096]; DWORD read = 0;
    while (ReadFile(hFile, buffer, sizeof(buffer), &read, nullptr) && read > 0) {
        if (!CryptHashData(cr.hHash, buffer, read, 0))
            return {};
    }

    BYTE md5[16]; DWORD md5len = sizeof(md5);
    if (!CryptGetHashParam(cr.hHash, HP_HASHVAL, md5, &md5len, 0))
        return {};

    wchar_t hex[33] = {0};
    for (int i = 0; i < 16; ++i)
        swprintf_s(hex + i * 2, 33 - i * 2, L"%02x", md5[i]);
    return hex;
}
}
