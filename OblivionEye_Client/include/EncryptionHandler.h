#pragma once
#include <string>
#include "Config.h"

// Client-side EncryptionHandler (harus cocok dengan server)
// Menggunakan XOR + Base64 sederhana (demo only)
class EncryptionHandler {
private:
    std::string encryptionKey;
    bool useEncryption;

    std::string xorEncryptDecrypt(const std::string& data, const std::string& key);
    std::string base64Encode(const std::string& data);
    std::string base64Decode(const std::string& encoded);
public:
    EncryptionHandler(const std::string& key = std::string(), bool enableEncryption = true)
        : encryptionKey(key.empty() ? Config::Get().encryptionKey : key), useEncryption(enableEncryption) {}

    std::string encryptMessage(const std::string& message);
    std::string decryptMessage(const std::string& encryptedMessage);
    bool isEncryptionEnabled() const { return useEncryption; }
};
