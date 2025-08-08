#include "EncryptionHandler.h"
#include <algorithm>
#include <stdexcept>
#include <ctime>
#include <sstream>

EncryptionHandler::EncryptionHandler(const std::string& key, bool enableEncryption)
    : encryptionKey(key), useEncryption(enableEncryption) {
}

std::string EncryptionHandler::xorEncryptDecrypt(const std::string& data, const std::string& key) {
    if (key.empty()) {
        return data;
    }

    std::string result;
    result.reserve(data.length());

    for (size_t i = 0; i < data.length(); ++i) {
        result += data[i] ^ key[i % key.length()];
    }

    return result;
}

// Simple Base64 implementation
static const std::string base64_chars =
"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"abcdefghijklmnopqrstuvwxyz"
"0123456789+/";

std::string EncryptionHandler::base64Encode(const std::string& data) {
    std::string ret;
    int val = 0, valb = -6;

    for (unsigned char c : data) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            ret.push_back(base64_chars[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }

    if (valb > -6) {
        ret.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
    }

    while (ret.size() % 4) {
        ret.push_back('=');
    }

    return ret;
}

std::string EncryptionHandler::base64Decode(const std::string& encoded) {
    std::string ret;
    int val = 0, valb = -8;

    for (unsigned char c : encoded) {
        if (c == '=') break;

        int pos = base64_chars.find(c);
        if (pos == std::string::npos) continue;

        val = (val << 6) + pos;
        valb += 6;
        if (valb >= 0) {
            ret.push_back(char((val >> valb) & 0xFF));
            valb -= 8;
        }
    }

    return ret;
}

std::string EncryptionHandler::encryptMessage(const std::string& message) {
    if (!useEncryption || message.empty()) {
        return message;
    }

    try {
        // XOR encrypt
        std::string encrypted = xorEncryptDecrypt(message, encryptionKey);
        // Base64 encode for safe transmission
        return base64Encode(encrypted);
    }
    catch (...) {
        // If encryption fails, return original message
        return message;
    }
}

std::string EncryptionHandler::decryptMessage(const std::string& encryptedMessage) {
    if (!useEncryption || encryptedMessage.empty()) {
        return encryptedMessage;
    }

    try {
        // Base64 decode
        std::string decoded = base64Decode(encryptedMessage);
        // XOR decrypt
        return xorEncryptDecrypt(decoded, encryptionKey);
    }
    catch (...) {
        // If decryption fails, return original message
        return encryptedMessage;
    }
}

void EncryptionHandler::setEncryptionKey(const std::string& key) {
    if (!key.empty()) {
        encryptionKey = key;
    }
}

std::string EncryptionHandler::generateSessionKey() {
    // Simple session key generation
    std::time_t now = std::time(nullptr);
    std::stringstream ss;
    ss << "Session_" << now << "_Key";
    return ss.str();
}