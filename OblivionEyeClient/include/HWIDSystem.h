#pragma once
#include <string>

class HWIDSystem {
public:
    static std::string GenerateHWID();
    static std::string GetCPUID();
    static std::string GetDiskSerial();
    static std::string GetMACAddress();
    static std::string HashString(const std::string& str);
};