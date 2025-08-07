#pragma once
#include <string>
#include <vector>
#include <map>

// Struktur untuk menyimpan informasi file dan hash-nya
struct FileInfo {
    std::string relativePath;  // Path relatif terhadap direktori client
    std::string expectedMD5;   // Hash MD5 yang diharapkan (dalam hex string)
    // Bisa tambah CRC32 jika diperlukan
    // uint32_t expectedCRC32;
};

// Deklarasi fungsi
std::string CalculateFileMD5(const std::string& filePath);
bool VerifyFileIntegrity(const FileInfo& fileInfo);
bool PerformFileIntegrityCheck();
void ContinuousFileIntegrityCheck();