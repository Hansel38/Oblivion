#pragma once
#include <string>
#include <vector>

class FileIntegrity {
public:
    static bool IsFileIntegrityCompromised();
private:
    static std::string CalculateMD5(const std::string& filepath);
    static bool VerifyFile(const std::string& filepath, const std::string& expectedMD5);
};

// Struktur untuk file whitelist
struct WhitelistedFile {
    std::string path;
    std::string md5; // Hanya MD5
};