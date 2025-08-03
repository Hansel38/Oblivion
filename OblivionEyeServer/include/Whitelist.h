// OblivionEye.Server/Whitelist.h
#pragma once
#include <string>
#include <unordered_set>

class HWIDWhitelist {
public:
    static bool IsHWIDAllowed(const std::string& hwid);
    static void LoadWhitelist(); // Bisa load dari file nanti
private:
    static std::unordered_set<std::string> allowedHWIDs;
};