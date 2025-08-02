#include "../include/MemoryScanner.h"
#include "../include/Logger.h"
#include <windows.h>
#include <psapi.h>
#include <vector>
#include <cmath>
#include <algorithm> // Untuk min()

#pragma comment(lib, "psapi.lib")

// Helper: Hitung entropi
double MemoryScanner::CalculateEntropy(const unsigned char* data, size_t size) {
    if (size == 0) return 0.0;

    int frequency[256] = { 0 };
    for (size_t i = 0; i < size; ++i) {
        frequency[data[i]]++;
    }

    double entropy = 0.0;
    for (int i = 0; i < 256; ++i) {
        if (frequency[i] == 0) continue;
        double p = (double)frequency[i] / size;
        entropy -= p * log2(p);
    }
    return entropy;
}

// 1. Scan RWX Memory
bool MemoryScanner::ScanRWXMemory() {
    MEMORY_BASIC_INFORMATION mbi;
    DWORD start = 0x00400000; // Base biasa client
    DWORD end = 0x7FFFFFFF;

    for (DWORD addr = start; addr < end; addr += mbi.RegionSize) {
        if (VirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi)) == 0)
            break;

        // Abaikan region kecil
        if (mbi.RegionSize < 0x1000) // Kurang dari 4KB
            continue;

        // Cek RWX
        if ((mbi.Protect & PAGE_EXECUTE_READWRITE) == PAGE_EXECUTE_READWRITE) {
            // Filter stack dan heap
            if (mbi.Type == MEM_PRIVATE) {
                Logger::LogDetected("Suspicious RWX memory region found at: 0x" + std::to_string((DWORD)addr));
                return true;
            }
        }
    }
    return false;
}

// 2. Scan Entropi Tinggi - DIPERBAIKI untuk warning
bool MemoryScanner::ScanHighEntropy() {
    MEMORY_BASIC_INFORMATION mbi;
    DWORD start = 0x00400000;
    DWORD end = 0x7FFFFFFF;

    for (DWORD addr = start; addr < end; addr += mbi.RegionSize) {
        if (VirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi)) == 0)
            break;

        // Validasi alamat tidak nol
        if (addr == 0 || mbi.BaseAddress == nullptr)
            continue;

        // Hanya scan region executable
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & PAGE_EXECUTE_READ ||
                mbi.Protect & PAGE_EXECUTE_READWRITE ||
                mbi.Protect & PAGE_EXECUTE_WRITECOPY)) {

            // Abaikan region kecil
            if (mbi.RegionSize < 0x2000) // Kurang dari 8KB
                continue;

            // Validasi ukuran buffer
            size_t readSize = min(2048, mbi.RegionSize);
            if (readSize == 0)
                continue;

            // Baca untuk entropi
            std::vector<unsigned char> buffer(readSize);
            if (ReadProcessMemory(GetCurrentProcess(), mbi.BaseAddress, buffer.data(), readSize, nullptr)) {
                double entropy = CalculateEntropy(buffer.data(), readSize);

                // Threshold tinggi
                if (entropy > 7.9) {
                    // Cek pola executable
                    bool hasExecPattern = false;
                    for (size_t i = 0; i < min(readSize, (size_t)512); i++) {
                        if (buffer[i] == 0x55 || buffer[i] == 0x48 || buffer[i] == 0x8B) {
                            hasExecPattern = true;
                            break;
                        }
                    }

                    if (hasExecPattern) {
                        DWORD regionAddr = (DWORD)mbi.BaseAddress;
                        Logger::LogDetected("High entropy + exec pattern at: 0x" + std::to_string(regionAddr));
                        return true;
                    }
                }
            }
        }
    }
    return false;
}

// 3. Cek IAT Integrity
bool MemoryScanner::CheckIATIntegrity() {
    // Skip untuk versi dasar
    return false;
}

// 4. Scan Inline Hook (JMP/CALL di prologue)
bool MemoryScanner::ScanInlineHooks() {
    HMODULE hModule = GetModuleHandleA(NULL);
    if (!hModule) return false;

    MODULEINFO modInfo = { 0 };
    if (!GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(modInfo)))
        return false;

    DWORD base = (DWORD)modInfo.lpBaseOfDll;
    DWORD size = modInfo.SizeOfImage;

    // Hanya scan fungsi-fungsi utama (contoh)
    // Untuk sekarang kita skip dulu untuk menghindari false positive
    Logger::Log("Inline hook scan skipped (to avoid false positive)");
    return false;
}

// Fungsi utama
bool MemoryScanner::IsMemoryTampered() {
    if (ScanRWXMemory()) return true;
    // Skip entropy scan sementara karena false positive
    // if (ScanHighEntropy()) return true;
    // Inline hook juga diskip dulu
    return false;
}