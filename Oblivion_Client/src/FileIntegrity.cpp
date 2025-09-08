#include "../pch.h"
#include "../include/FileIntegrity.h"
#include <windows.h>
#include <wincrypt.h>
#include <string>
#pragma comment(lib, "advapi32.lib")

namespace OblivionEye {

    std::wstring MD5OfFile(const std::wstring& path) {
        std::wstring result;
        HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) return result;

        HCRYPTPROV hProv = 0; HCRYPTHASH hHash = 0;
        if (!CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) { CloseHandle(hFile); return result; }
        if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) { CryptReleaseContext(hProv, 0); CloseHandle(hFile); return result; }

        BYTE buffer[4096]; DWORD read = 0;
        while (ReadFile(hFile, buffer, sizeof(buffer), &read, nullptr) && read > 0) {
            CryptHashData(hHash, buffer, read, 0);
        }

        BYTE md5[16]; DWORD md5len = sizeof(md5);
        if (CryptGetHashParam(hHash, HP_HASHVAL, md5, &md5len, 0)) {
            wchar_t hex[33];
            for (int i = 0; i < 16; ++i) swprintf_s(hex + i*2, 33 - i*2, L"%02x", md5[i]);
            result = hex;
        }
        CryptDestroyHash(hHash); CryptReleaseContext(hProv, 0); CloseHandle(hFile);
        return result;
    }
}
