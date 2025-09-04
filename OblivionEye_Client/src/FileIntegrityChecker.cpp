#include "../include/FileIntegrityChecker.h"
#include <windows.h>
#include <wincrypt.h> // Untuk CryptoAPI
#include <fstream>
#include <sstream>
#include <iomanip>
#include <thread>
#include <chrono>
#include "../include/Logger.h"
#include "../include/DetectionController.h"
#include "../include/SleepUtil.h"

#pragma comment(lib, "advapi32.lib") // Library untuk Cryptography API

// DEFINISI SEBENARNYA (menggantikan deklarasi extern sebelumnya)
// TODO: Ganti hash MD5 dengan nilai asli produksi.
const std::vector<FileInfo> importantFiles = {
    {"RRO.exe", "67e75d25e9cc99c8cd0d4d4147c5ed70"},
    {"data.grf", "dd1cd395cad741f29b61d8311d6d216c"}
};

// Fungsi untuk menghitung MD5 dari file
std::string CalculateFileMD5(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        Logger::Log(LOG_ERROR, "Cannot open file for MD5 calculation: " + filePath);
        return "";
    }
    HCRYPTPROV hProv = 0; HCRYPTHASH hHash = 0; std::string md5Hash;
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        Logger::Log(LOG_ERROR, "CryptAcquireContext failed for MD5. Error: " + std::to_string(GetLastError()));
        return "";
    }
    if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
        Logger::Log(LOG_ERROR, "CryptCreateHash failed for MD5. Error: " + std::to_string(GetLastError()));
        CryptReleaseContext(hProv, 0); return ""; }
    const size_t BUFFER_SIZE = 8192; char buffer[BUFFER_SIZE];
    while (file.read(buffer, BUFFER_SIZE) || file.gcount() > 0) {
        if (!CryptHashData(hHash, (BYTE*)buffer, static_cast<DWORD>(file.gcount()), 0)) {
            Logger::Log(LOG_ERROR, "CryptHashData failed for MD5. Error: " + std::to_string(GetLastError()));
            CryptDestroyHash(hHash); CryptReleaseContext(hProv, 0); return ""; }
    }
    BYTE rgbHash[16]; DWORD cbHash = 16;
    if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0)) {
        std::stringstream ss; ss << std::hex << std::setfill('0');
        for (DWORD i = 0; i < cbHash; i++) ss << std::setw(2) << static_cast<int>(rgbHash[i]);
        md5Hash = ss.str();
    } else {
        Logger::Log(LOG_ERROR, "CryptGetHashParam failed for MD5. Error: " + std::to_string(GetLastError()));
    }
    CryptDestroyHash(hHash); CryptReleaseContext(hProv, 0); return md5Hash; }

bool VerifyFileIntegrity(const FileInfo& fileInfo) {
    char exePath[MAX_PATH]; GetModuleFileNameA(NULL, exePath, MAX_PATH); std::string exeDir(exePath);
    size_t lastSlash = exeDir.find_last_of("\\/"); if (lastSlash != std::string::npos) exeDir = exeDir.substr(0, lastSlash + 1);
    std::string fullPath = exeDir + fileInfo.relativePath;
    Logger::Log(LOG_INFO, "Verifying integrity of: " + fullPath);
    std::string currentMD5 = CalculateFileMD5(fullPath);
    if (currentMD5.empty()) { Logger::Log(LOG_ERROR, "Failed to calculate MD5 for: " + fullPath); return false; }
    if (_stricmp(currentMD5.c_str(), fileInfo.expectedMD5.c_str()) == 0) {
        Logger::Log(LOG_INFO, "File integrity OK: " + fullPath + " (MD5: " + currentMD5 + ")"); return true;
    } else {
        Logger::Log(LOG_DETECTED, "File integrity check FAILED! File: " + fullPath + " Expected MD5: " + fileInfo.expectedMD5 + " Current MD5: " + currentMD5); return false; }
}

bool PerformFileIntegrityCheck() {
    Logger::Log(LOG_INFO, "Starting file integrity check for " + std::to_string(importantFiles.size()) + " files...");
    bool allFilesOK = true; for (const auto& fi : importantFiles) { if (!VerifyFileIntegrity(fi)) allFilesOK = false; }
    if (allFilesOK) Logger::Log(LOG_INFO, "All file integrity checks passed."); else Logger::Log(LOG_INFO, "File integrity check completed with failures.");
    return allFilesOK;
}

void ContinuousFileIntegrityCheck() {
    Logger::Log(LOG_INFO, "File Integrity Checker started");
    SleepWithStopSeconds(120); if (DetectionController::IsStopRequested()) return;
    if (!PerformFileIntegrityCheck()) { DetectionController::ReportDetection("File integrity failure at startup"); return; }
    while (!DetectionController::IsStopRequested()) {
        SleepWithStopSeconds(300); if (DetectionController::IsStopRequested()) break;
        if (!PerformFileIntegrityCheck()) { DetectionController::ReportDetection("File integrity failure during runtime"); break; }
    }
    Logger::Log(LOG_INFO, "File Integrity Checker thread exiting");
}