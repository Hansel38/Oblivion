#include "../pch.h"
#include "../include/FileIntegrity.h"
#include <windows.h>
//#include <wincrypt.h> // legacy removed
#include <string>
#include <bcrypt.h>

// Link: bcrypt.lib (Windows CNG) should be linked automatically in modern VS; else add manually.

namespace OblivionEye {
namespace {
    struct HandleCloser { HANDLE h; ~HandleCloser(){ if(h && h!=INVALID_HANDLE_VALUE) CloseHandle(h); } };
}

// Compute SHA-256 of file, return lowercase hex wstring (empty on failure)
std::wstring Sha256FileHex(const std::wstring &path) {
    HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return {};
    HandleCloser file{hFile};

    BCRYPT_ALG_HANDLE hAlg = nullptr; BCRYPT_HASH_HANDLE hHash = nullptr; NTSTATUS st;
    st = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0); if(st!=0) return {};
    st = BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0); if(st!=0){ BCryptCloseAlgorithmProvider(hAlg,0); return {}; }

    BYTE buffer[4096]; DWORD read=0;
    while (ReadFile(hFile, buffer, sizeof(buffer), &read, nullptr) && read>0) {
        st = BCryptHashData(hHash, buffer, read, 0);
        if(st!=0){ BCryptDestroyHash(hHash); BCryptCloseAlgorithmProvider(hAlg,0); return {}; }
    }
    UCHAR hash[32]; st = BCryptFinishHash(hHash, hash, sizeof(hash), 0);
    if(st!=0){ BCryptDestroyHash(hHash); BCryptCloseAlgorithmProvider(hAlg,0); return {}; }
    BCryptDestroyHash(hHash); BCryptCloseAlgorithmProvider(hAlg,0);

    static const wchar_t* hexDigits = L"0123456789abcdef";
    std::wstring out; out.resize(64);
    for(size_t i=0;i<32;++i){ out[i*2] = hexDigits[(hash[i]>>4)&0xF]; out[i*2+1]=hexDigits[hash[i]&0xF]; }
    return out;
}
}
