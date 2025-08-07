#include "../include/MemoryScanner.h"
#include <windows.h>
#include <vector>
#include <thread>
#include <chrono>
#include <iostream>
#include "../include/Logger.h"

// Fungsi untuk membandingkan data dengan pattern dan mask
bool DataCompare(const unsigned char* pData, const unsigned char* bMask, const char* szMask) {
    for (; *szMask; ++szMask, ++pData, ++bMask) {
        if (*szMask == 'x' && *pData != *bMask) {
            return false;
        }
    }
    return (*szMask) == 0;
}

// Fungsi untuk mencari alamat berdasarkan pattern dan mask
uintptr_t FindPattern(uintptr_t dwAddress, uintptr_t dwLen, unsigned char* bMask, const char* szMask) {
    for (uintptr_t i = 0; i < dwLen; i++) {
        if (DataCompare((unsigned char*)(dwAddress + i), bMask, szMask)) {
            return (uintptr_t)(dwAddress + i);
        }
    }
    return 0;
}

// Fungsi untuk mendapatkan semua region memori yang dapat dibaca
std::vector<MEMORY_BASIC_INFORMATION> GetMemoryRegions(HANDLE hProcess) {
    std::vector<MEMORY_BASIC_INFORMATION> regions;
    MEMORY_BASIC_INFORMATION mbi;
    uintptr_t address = 0;

    while (VirtualQueryEx(hProcess, (LPCVOID)address, &mbi, sizeof(mbi))) {
        // Hanya proses region yang COMMIT dan readable
        // PAGE_READABLE bukan konstanta standar, kita harus cek flag secara manual
        if (mbi.State == MEM_COMMIT) {
            // Cek apakah memori dapat dibaca (PAGE_READONLY, PAGE_READWRITE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE)
            if ((mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) != 0) {
                // Abaikan region yang guard atau noaccess
                if (!(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS))) {
                    regions.push_back(mbi);
                }
            }
        }
        address = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        // Batasi pencarian untuk menghindari crash pada alamat tinggi
        if (address >= 0x7FFFFFFFFFFF) break; // Batas atas user-mode address space
    }

    return regions;
}

// Daftar signature untuk dideteksi
// PERINGATAN: Signature ini hanya untuk demonstrasi. Signature nyata harus diteliti lebih lanjut.
const std::vector<SignatureInfo> signatures = {
    // Contoh signature untuk Speed Hack (ini hanya contoh, bukan signature nyata)
    // {
    //     "SpeedHack_Example",
    //     { 0x8B, 0x45, 0xFC, 0x83, 0xC0, 0x01, 0x89, 0x45, 0xFC }, // Pattern
    //     "xxxxxxxxx", // Mask
    //     0
    // },
    // Contoh signature untuk Freeze Hack
    // {
    //     "FreezeHack_Example",
    //     { 0x90, 0x90, 0x90, 0x90, 0xEB, 0xFE }, // Pattern NOP NOP NOP NOP JMP SHORT $-2
    //     "xxxxxx", // Mask
    //     0
    // },
    // Signature umum untuk injector atau hooking framework (contoh)
    {
        "Generic_Injector_Signature",
        { 0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00 }, // Potongan header PE umum
        "xxxxxxxxxxxx", // Mask
        0
    }
    // Tambahkan signature lainnya di sini
    // PENTING: Signature harus akurat dan spesifik untuk menghindari false positive.
};

// Fungsi untuk scan memori berdasarkan signature
bool ScanMemoryForSignatures() {
    HANDLE hProcess = GetCurrentProcess();
    auto regions = GetMemoryRegions(hProcess);

    Logger::Log(LOG_INFO, "Starting memory scan for " + std::to_string(signatures.size()) + " signatures...");

    for (const auto& sig : signatures) {
        Logger::Log(LOG_INFO, "Scanning for signature: " + sig.name);

        for (const auto& region : regions) {
            // Abaikan region yang terlalu kecil
            if (region.RegionSize < sig.pattern.size()) {
                continue;
            }

            // Alokasi buffer untuk membaca memori
            std::vector<unsigned char> buffer(region.RegionSize);
            SIZE_T bytesRead = 0;

            // Baca memori region
            if (ReadProcessMemory(hProcess, region.BaseAddress, buffer.data(), region.RegionSize, &bytesRead)) {
                // Cari pattern dalam buffer
                uintptr_t foundAddr = FindPattern(
                    (uintptr_t)buffer.data(),
                    bytesRead - sig.pattern.size(),
                    (unsigned char*)sig.pattern.data(),
                    sig.mask.c_str()
                );

                if (foundAddr) {
                    // Hitung alamat virtual asli
                    uintptr_t realAddr = (uintptr_t)region.BaseAddress + (foundAddr - (uintptr_t)buffer.data());
                    Logger::Log(LOG_DETECTED, "Signature '" + sig.name + "' detected at address: 0x" + std::to_string(realAddr));
                    // Jangan return true langsung, scan semua signature dulu untuk log lengkap
                    // Tapi untuk demo, kita return true jika menemukan satu
                    // return true;
                }
            }
            else {
                // Log error membaca memori jika diperlukan, tapi jangan spam
                // DWORD err = GetLastError();
                // if (err != ERROR_PARTIAL_COPY && err != ERROR_NOACCESS) {
                //     Logger::Log(LOG_ERROR, "Failed to read memory region. Error: " + std::to_string(err));
                // }
            }
        }
    }

    Logger::Log(LOG_INFO, "Memory scan completed.");
    // Untuk demo, return false. Ubah jika benar-benar menemukan signature.
    return false;
}


// Fungsi untuk scanning continuous
void ContinuousMemoryScan() {
    Logger::Log(LOG_INFO, "Memory Signature Scanner started");

    // Delay awal 45 detik untuk memastikan game sepenuhnya dimuat
    std::this_thread::sleep_for(std::chrono::seconds(45));

    // Scan pertama kali saat startup
    if (ScanMemoryForSignatures()) {
        Logger::Log(LOG_DETECTED, "Malicious memory signature detected on startup, closing client");
        ExitProcess(0);
    }

    // Scan terus-menerus setiap 120 detik (2 menit - cukup jarang untuk tidak membebani)
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(120));
        if (ScanMemoryForSignatures()) {
            Logger::Log(LOG_DETECTED, "Malicious memory signature detected during runtime, closing client");
            ExitProcess(0);
        }
    }
}