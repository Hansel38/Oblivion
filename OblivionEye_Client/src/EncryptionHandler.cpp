#include "../include/EncryptionHandler.h"
#include <stdexcept>

static const std::string base64_chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

std::string EncryptionHandler::xorEncryptDecrypt(const std::string& data, const std::string& key) {
    if (key.empty()) return data;
    std::string result; result.reserve(data.size());
    for (size_t i = 0; i < data.size(); ++i) {
        result.push_back(data[i] ^ key[i % key.size()]);
    }
    return result;
}

std::string EncryptionHandler::base64Encode(const std::string& data) {
    std::string ret; int val = 0, valb = -6;
    for (unsigned char c : data) {
        val = (val << 8) + c; valb += 8;
        while (valb >= 0) { ret.push_back(base64_chars[(val >> valb) & 0x3F]); valb -= 6; }
    }
    if (valb > -6) ret.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
    while (ret.size() % 4) ret.push_back('=');
    return ret;
}

std::string EncryptionHandler::base64Decode(const std::string& encoded) {
    std::string ret; int val = 0, valb = -8;
    for (unsigned char c : encoded) {
        if (c == '=') break; int pos = (int)base64_chars.find(c); if (pos == std::string::npos) continue;
        val = (val << 6) + pos; valb += 6;
        if (valb >= 0) { ret.push_back(char((val >> valb) & 0xFF)); valb -= 8; }
    }
    return ret;
}

std::string EncryptionHandler::encryptMessage(const std::string& message) {
    if (!useEncryption || message.empty()) return message;
    try { return base64Encode(xorEncryptDecrypt(message, encryptionKey)); } catch (...) { return message; }
}

std::string EncryptionHandler::decryptMessage(const std::string& encryptedMessage) {
    if (!useEncryption || encryptedMessage.empty()) return encryptedMessage;
    try { return xorEncryptDecrypt(base64Decode(encryptedMessage), encryptionKey); } catch (...) { return encryptedMessage; }
}
