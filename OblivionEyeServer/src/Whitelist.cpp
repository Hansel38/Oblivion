// OblivionEye.Server/Whitelist.cpp
#include "Whitelist.h"
#include <iostream>

// Static member definition
std::unordered_set<std::string> HWIDWhitelist::allowedHWIDs;

// Cek apakah HWID diizinkan
bool HWIDWhitelist::IsHWIDAllowed(const std::string& hwid) {
    return allowedHWIDs.find(hwid) != allowedHWIDs.end();
}

// Load whitelist (bisa dari file/database nanti)
void HWIDWhitelist::LoadWhitelist() {
    // Tambahkan HWID yang diizinkan
    allowedHWIDs.insert("ce9e58c");        // Contoh HWID client kamu
    allowedHWIDs.insert("VALID_HWID_123"); // Contoh lain
    allowedHWIDs.insert("ABCDEF123456");   // Tambahkan sesuai kebutuhan

    std::cout << "[Whitelist] Loaded " << allowedHWIDs.size() << " allowed HWIDs\n";
}