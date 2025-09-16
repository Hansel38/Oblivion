#pragma once
#include <string>
#include <array>
#include <cstdint>

namespace OblivionEye::HashUtil {
    // Menghasilkan SHA-256 lowercase hex; return empty string jika gagal.
    std::string Sha256HexLower(const std::string& data);

    // Raw SHA-256 (32 bytes). Returns true on success.
    bool Sha256(const void* data, size_t len, unsigned char out[32]);

    // Truncated 64-bit (little-endian) of SHA-256. (Equivalent to first 8 bytes of raw hash interpreted LE)
    inline uint64_t Sha256Trunc64(const void* data, size_t len) {
        unsigned char h[32]; if(!Sha256(data,len,h)) return 0ULL; 
        uint64_t v=0; for(int i=0;i<8;++i) v |= (uint64_t)h[i] << (i*8); return v; // LE assembly for portability
    }

    // Derive session key from shared key + client nonce + server nonce (all hex strings concatenated)
    inline std::string DeriveSessionKey(const std::string& sharedKeyUtf8, const std::string& nonceCliHex, const std::string& nonceSrvHex) {
        return Sha256HexLower(sharedKeyUtf8 + nonceCliHex + nonceSrvHex);
    }
}
