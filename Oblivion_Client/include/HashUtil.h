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

    // Simple HMAC-SHA256 (key/data in memory). Returns true on success.
    inline bool HmacSha256(const void* key, size_t keyLen, const void* data, size_t dataLen, unsigned char out[32]) {
        if(!out) return false;
        // RFC 2104 style: if key > block (64) hash first
        unsigned char kh[32]; const unsigned char* kbytes = static_cast<const unsigned char*>(key);
        if(keyLen > 64){ if(!Sha256(key, keyLen, kh)) return false; kbytes = kh; keyLen = 32; }
        unsigned char kipad[64]; unsigned char kopad[64]; memset(kipad,0,64); memset(kopad,0,64); memcpy(kipad,kbytes,keyLen); memcpy(kopad,kbytes,keyLen);
        for(int i=0;i<64;++i){ kipad[i]^=0x36; kopad[i]^=0x5c; }
        unsigned char inner[32]; if(!Sha256(kipad,64,inner)) return false; // This is not correct; need streaming variant for large data, so fallback to manual concatenation below.
        // Re-implement without streaming bcrypt overhead: just concatenate buffers: kipad || data
        std::vector<unsigned char> tmp; tmp.reserve(64 + dataLen); tmp.insert(tmp.end(), kipad, kipad+64); tmp.insert(tmp.end(), (const unsigned char*)data, (const unsigned char*)data + dataLen);
        if(!Sha256(tmp.data(), tmp.size(), inner)) return false;
        std::vector<unsigned char> tmp2; tmp2.reserve(64 + 32); tmp2.insert(tmp2.end(), kopad, kopad+64); tmp2.insert(tmp2.end(), inner, inner+32);
        return Sha256(tmp2.data(), tmp2.size(), out);
    }
}
