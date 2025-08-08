#ifndef ENCRYPTION_HANDLER_H
#define ENCRYPTION_HANDLER_H

#include <string>
#include <vector>
#include <memory>

// Simple XOR encryption for demonstration
// In production, use proper encryption like AES
class EncryptionHandler {
private:
    std::string encryptionKey;
    bool useEncryption;

    // Simple XOR encryption
    std::string xorEncryptDecrypt(const std::string& data, const std::string& key);

    // Base64 encoding/decoding (for safe transmission)
    std::string base64Encode(const std::string& data);
    std::string base64Decode(const std::string& encoded);

public:
    EncryptionHandler(const std::string& key = "OblivionEye_Secret_Key_2025",
        bool enableEncryption = true);

    // Encrypt message
    std::string encryptMessage(const std::string& message);

    // Decrypt message
    std::string decryptMessage(const std::string& encryptedMessage);

    // Check if encryption is enabled
    bool isEncryptionEnabled() const { return useEncryption; }

    // Set encryption key
    void setEncryptionKey(const std::string& key);

    // Generate session key (for future use)
    std::string generateSessionKey();
};

#endif // ENCRYPTION_HANDLER_H