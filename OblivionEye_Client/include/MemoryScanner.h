#pragma once
#include <string>
#include <vector>

// Struktur untuk menyimpan informasi signature
struct SignatureInfo {
    std::string name;        // Nama cheat/signature
    std::vector<unsigned char> pattern; // Pola byte
    std::string mask;        // Mask (misalnya: "x" untuk byte yang harus cocok, "?" untuk wildcard)
    size_t offset;           // Offset untuk menemukan alamat yang sebenarnya
};

// Deklarasi fungsi
bool ScanMemoryForSignatures();
void ContinuousMemoryScan();