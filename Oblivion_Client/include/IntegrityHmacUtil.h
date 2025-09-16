#pragma once
#include <vector>
#include <string>

namespace OblivionEye {
    namespace IntegrityHmacUtil {
        // Build a 32-byte obfuscated base key, mix HWID (optional), then XOR module name
        void BuildModuleKey(const wchar_t* moduleName, std::vector<unsigned char>& outKey, bool mixHwid);
        // Raw HMAC-SHA256 using central HashUtil::Sha256 (data/key arbitrary length)
        bool HmacSha256(const unsigned char* key, size_t keyLen, const unsigned char* data, size_t dataLen, unsigned char out[32]);
    }
}
