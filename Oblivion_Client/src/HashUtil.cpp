#include "../pch.h"
#include "../include/HashUtil.h"
#include <bcrypt.h>
#include <vector>

// Link note: ensure linker links bcrypt.lib (usually automatic via VS when including <bcrypt.h>)

namespace OblivionEye::HashUtil {

    bool Sha256(const void* data, size_t len, unsigned char out[32]) {
        if(!out) return false;
        BCRYPT_ALG_HANDLE hAlg = nullptr; BCRYPT_HASH_HANDLE hHash = nullptr; bool ok=false;
        NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
        if (status != 0) return false;
        DWORD hashLen = 0, cbData = 0;
        status = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PUCHAR)&hashLen, sizeof(hashLen), &cbData, 0);
        if (status != 0 || hashLen != 32) { BCryptCloseAlgorithmProvider(hAlg, 0); return false; }
        status = BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0);
        if (status != 0) { BCryptCloseAlgorithmProvider(hAlg, 0); return false; }
        if (len) {
            status = BCryptHashData(hHash, (PUCHAR)data, (ULONG)len, 0);
            if (status != 0) { BCryptDestroyHash(hHash); BCryptCloseAlgorithmProvider(hAlg, 0); return false; }
        }
        status = BCryptFinishHash(hHash, out, 32, 0);
        if (status == 0) ok=true;
        BCryptDestroyHash(hHash); BCryptCloseAlgorithmProvider(hAlg,0); return ok;
    }

    std::string Sha256HexLower(const std::string& data) {
        unsigned char h[32]; if(!Sha256(data.data(), data.size(), h)) return {};
        static const char* hex = "0123456789abcdef"; std::string out; out.resize(64);
        for (size_t i = 0; i < 32; ++i) { out[i*2]=hex[(h[i]>>4)&0xF]; out[i*2+1]=hex[h[i]&0xF]; }
        return out;
    }
}
