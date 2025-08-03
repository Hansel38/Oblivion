#include "../include/FileIntegrity.h"
#include "../include/Logger.h"
#include <windows.h>
#include <wincrypt.h>
#include <fstream>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "advapi32.lib")

// Helper: Baca file ke buffer
std::vector<unsigned char> ReadFileToBuffer(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary | std::ios::ate);
    if (!file) {
        Logger::Log("Failed to open file: " + filepath);
        return {};
    }

    std::streamoff size = file.tellg(); // Gunakan streamoff
    if (size <= 0) {
        Logger::Log("File is empty or invalid: " + filepath);
        return {};
    }

    file.seekg(0, std::ios::beg);

    // Cast ke size_t dengan aman
    std::vector<unsigned char> buffer(static_cast<size_t>(size));
    if (!file.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(size))) {
        Logger::Log("Failed to read file: " + filepath);
        return {};
    }

    return buffer;
}

// Hitung MD5
std::string FileIntegrity::CalculateMD5(const std::string& filepath) {
    std::vector<unsigned char> buffer = ReadFileToBuffer(filepath);
    if (buffer.empty()) return "";

    HCRYPTPROV hProv = 0;
    if (!CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        Logger::Log("CryptAcquireContext failed for file: " + filepath);
        return "";
    }

    HCRYPTHASH hHash = 0;
    if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        Logger::Log("CryptCreateHash failed for file: " + filepath);
        return "";
    }

    if (!CryptHashData(hHash, buffer.data(), static_cast<DWORD>(buffer.size()), 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        Logger::Log("CryptHashData failed for file: " + filepath);
        return "";
    }

    BYTE rgbHash[16];
    DWORD cbHash = 16;
    if (!CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        Logger::Log("CryptGetHashParam failed for file: " + filepath);
        return "";
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    std::stringstream ss;
    for (DWORD i = 0; i < cbHash; i++) {
        ss << std::hex << std::uppercase << std::setfill('0') << std::setw(2) << static_cast<int>(rgbHash[i]);
    }

    return ss.str();
}

// Verifikasi file dengan MD5
bool FileIntegrity::VerifyFile(const std::string& filepath, const std::string& expectedMD5) {
    std::string currentMD5 = CalculateMD5(filepath);

    Logger::Log("Verifying file: " + filepath);
    Logger::Log("Expected MD5: " + expectedMD5 + " | Current MD5: " + currentMD5);

    if (currentMD5 != expectedMD5) {
        Logger::LogDetected("File integrity compromised: " + filepath);
        return true; // Compromised
    }

    return false; // OK
}

// Fungsi utama
bool FileIntegrity::IsFileIntegrityCompromised() {
    // Daftar file penting dengan MD5 asli (contoh)
    std::vector<WhitelistedFile> files = {
        // Ganti dengan MD5 asli file kamu
        {"RRO.exe", "8E9BEF1CE4BC732CD1577D63971A37AB"}, // Contoh MD5
        // Tambahkan file lain yang perlu dicek
    };

    for (const auto& file : files) {
        if (VerifyFile(file.path, file.md5)) {
            return true; // File compromised
        }
    }

    return false; // Semua file OK
}