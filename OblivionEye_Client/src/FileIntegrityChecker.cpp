#include "../include/FileIntegrityChecker.h"
#include <windows.h>
#include <wincrypt.h> // Untuk CryptoAPI
#include <fstream>
#include <sstream>
#include <iomanip>
#include <thread>
#include <chrono>
#include "../include/Logger.h"

#pragma comment(lib, "advapi32.lib") // Library untuk Cryptography API

// Fungsi untuk menghitung MD5 dari file
std::string CalculateFileMD5(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        Logger::Log(LOG_ERROR, "Cannot open file for MD5 calculation: " + filePath);
        return "";
    }

    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    std::string md5Hash = "";

    // Dapatkan handle provider kriptografi
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        Logger::Log(LOG_ERROR, "CryptAcquireContext failed for MD5. Error: " + std::to_string(GetLastError()));
        return "";
    }

    // Buat hash object untuk MD5
    if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
        Logger::Log(LOG_ERROR, "CryptCreateHash failed for MD5. Error: " + std::to_string(GetLastError()));
        CryptReleaseContext(hProv, 0);
        return "";
    }

    // Baca file dan tambahkan ke hash
    const size_t BUFFER_SIZE = 8192;
    char buffer[BUFFER_SIZE];
    while (file.read(buffer, BUFFER_SIZE) || file.gcount() > 0) {
        if (!CryptHashData(hHash, (BYTE*)buffer, static_cast<DWORD>(file.gcount()), 0)) {
            Logger::Log(LOG_ERROR, "CryptHashData failed for MD5. Error: " + std::to_string(GetLastError()));
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            return "";
        }
    }

    // Dapatkan hasil hash
    BYTE rgbHash[16]; // MD5 = 16 bytes
    DWORD cbHash = 16;
    if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0)) {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (DWORD i = 0; i < cbHash; i++) {
            ss << std::setw(2) << static_cast<int>(rgbHash[i]);
        }
        md5Hash = ss.str();
    }
    else {
        Logger::Log(LOG_ERROR, "CryptGetHashParam failed for MD5. Error: " + std::to_string(GetLastError()));
    }

    // Bersihkan
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    return md5Hash;
}

// Fungsi untuk memverifikasi integritas satu file
bool VerifyFileIntegrity(const FileInfo& fileInfo) {
    // Dapatkan path lengkap file (asumsi kita berada di direktori client)
    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    std::string exeDir(exePath);
    size_t lastSlash = exeDir.find_last_of("\\/");
    if (lastSlash != std::string::npos) {
        exeDir = exeDir.substr(0, lastSlash + 1);
    }

    std::string fullPath = exeDir + fileInfo.relativePath;

    Logger::Log(LOG_INFO, "Verifying integrity of: " + fullPath);

    // Hitung MD5 file saat ini
    std::string currentMD5 = CalculateFileMD5(fullPath);
    if (currentMD5.empty()) {
        Logger::Log(LOG_ERROR, "Failed to calculate MD5 for: " + fullPath);
        return false; // Anggap sebagai error/failure
    }

    // Bandingkan dengan MD5 yang diharapkan
    if (_stricmp(currentMD5.c_str(), fileInfo.expectedMD5.c_str()) == 0) {
        Logger::Log(LOG_INFO, "File integrity OK: " + fullPath + " (MD5: " + currentMD5 + ")");
        return true;
    }
    else {
        Logger::Log(LOG_DETECTED, "File integrity check FAILED! File: " + fullPath +
            " Expected MD5: " + fileInfo.expectedMD5 + " Current MD5: " + currentMD5);
        return false;
    }
}

// Daftar file penting dan hash MD5 yang diharapkan (CONTOH)
// Catatan: Hash MD5 ini adalah contoh dan TIDAK VALID. Kamu perlu menggantinya dengan hash sebenarnya.
const std::vector<FileInfo> importantFiles = {
    // Contoh:
    // {"RRO.exe", "d41d8cd98f00b204e9800998ecf8427e"}, // MD5 untuk file kosong
    // {"data.grf", "098f6bcd4621d373cade4e832627b4f6"}, // MD5 untuk "test"
    // {"sclient.dll", "c4ca4238a0b923820dcc509a6f75849b"} // MD5 untuk "1"

    // Untuk produksi, kamu perlu menghitung hash sebenarnya dari file asli kamu
    // dan memasukkannya ke sini.
    {"RRO.exe", "67e75d25e9cc99c8cd0d4d4147c5ed70"},
    {"data.grf", "dd1cd395cad741f29b61d8311d6d216c"}
    // Tambahkan file lain yang penting
};

// Fungsi utama untuk memeriksa integritas semua file
bool PerformFileIntegrityCheck() {
    Logger::Log(LOG_INFO, "Starting file integrity check for " + std::to_string(importantFiles.size()) + " files...");

    bool allFilesOK = true;
    for (const auto& fileInfo : importantFiles) {
        if (!VerifyFileIntegrity(fileInfo)) {
            allFilesOK = false;
            // Untuk demo, kita tidak return false langsung agar semua file diperiksa
            // Tapi dalam produksi, bisa return false segera
            // return false;
        }
    }

    if (allFilesOK) {
        Logger::Log(LOG_INFO, "All file integrity checks passed.");
    }
    else {
        Logger::Log(LOG_INFO, "File integrity check completed with failures.");
    }

    return allFilesOK;
}

// Fungsi untuk scanning continuous
void ContinuousFileIntegrityCheck() {
    Logger::Log(LOG_INFO, "File Integrity Checker started");

    // Delay awal 120 detik untuk memastikan file tidak sedang ditulis
    std::this_thread::sleep_for(std::chrono::seconds(120));

    // Periksa integritas saat startup
    if (!PerformFileIntegrityCheck()) {
        Logger::Log(LOG_DETECTED, "File integrity check failed on startup, closing client");
        ExitProcess(0);
    }

    // Periksa integritas secara berkala setiap 300 detik (5 menit)
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(300));
        if (!PerformFileIntegrityCheck()) {
            Logger::Log(LOG_DETECTED, "File integrity check failed during runtime, closing client");
            ExitProcess(0);
        }
    }
}