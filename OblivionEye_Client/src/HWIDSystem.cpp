#include "../include/HWIDSystem.h"
#include <windows.h>
#include <intrin.h> // Untuk __cpuid
#include <iphlpapi.h> // Untuk GetAdaptersInfo
#include <vector>
#include <sstream>
#include <iomanip>
#include <iostream>
#include "../include/Logger.h"

#pragma comment(lib, "iphlpapi.lib")

// --- TAMBAHKAN CACHE UNTUK HWID ---
static std::string g_cachedHWID = "";
// -----------------------------------

// Fungsi untuk mendapatkan CPUID
std::string GetCPUID() {
    int cpuInfo[4] = { 0 };
    __cpuid(cpuInfo, 0); // CPUID dengan fungsi 0 untuk mendapatkan signature

    std::stringstream ss;
    // Gabungkan EAX, EBX, ECX, EDX dari hasil CPUID
    ss << std::hex << std::setfill('0');
    ss << std::setw(8) << cpuInfo[0]; // EAX
    ss << std::setw(8) << cpuInfo[1]; // EBX
    ss << std::setw(8) << cpuInfo[2]; // ECX
    ss << std::setw(8) << cpuInfo[3]; // EDX

    return ss.str();
}

// Fungsi untuk mendapatkan Volume Serial Number dari disk
std::string GetDiskSerial() {
    DWORD serialNumber = 0;
    // Dapatkan serial number dari drive C:
    if (GetVolumeInformationA("C:\\", NULL, 0, &serialNumber, NULL, NULL, NULL, 0)) {
        std::stringstream ss;
        ss << std::hex << serialNumber;
        return ss.str();
    }
    else {
        Logger::Log(LOG_ERROR, "Failed to get disk serial number. Error: " + std::to_string(GetLastError()));
        return "UnknownDisk";
    }
}

// Fungsi untuk mendapatkan MAC Address
std::string GetMACAddress() {
    // Gunakan GetAdaptersInfo untuk mendapatkan adapter info
    ULONG outBufLen = sizeof(IP_ADAPTER_INFO);
    PIP_ADAPTER_INFO pAdapterInfo = (IP_ADAPTER_INFO*)malloc(outBufLen);

    // Dua percobaan, pertama untuk mendapatkan ukuran buffer yang dibutuhkan
    if (GetAdaptersInfo(pAdapterInfo, &outBufLen) == ERROR_BUFFER_OVERFLOW) {
        free(pAdapterInfo);
        pAdapterInfo = (IP_ADAPTER_INFO*)malloc(outBufLen);
    }

    if (GetAdaptersInfo(pAdapterInfo, &outBufLen) == NO_ERROR) {
        PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
        // Biasanya, adapter pertama yang aktif adalah yang utama
        // Tapi kita bisa iterasi untuk mencari yang terbaik
        while (pAdapter) {
            // Cek apakah adapter memiliki MAC address dan tidak kosong
            if (pAdapter->AddressLength > 0 &&
                !(pAdapter->Address[0] == 0 && pAdapter->Address[1] == 0 && pAdapter->Address[2] == 0 &&
                    pAdapter->Address[3] == 0 && pAdapter->Address[4] == 0 && pAdapter->Address[5] == 0)) {

                // Format MAC Address menjadi string hex
                std::stringstream ss;
                ss << std::hex << std::setfill('0');
                for (UINT i = 0; i < pAdapter->AddressLength; i++) {
                    ss << std::setw(2) << static_cast<unsigned int>(pAdapter->Address[i]);
                }
                free(pAdapterInfo);
                return ss.str();
            }
            pAdapter = pAdapter->Next;
        }
    }
    else {
        Logger::Log(LOG_ERROR, "Failed to get MAC address. Error: " + std::to_string(GetLastError()));
    }

    if (pAdapterInfo) {
        free(pAdapterInfo);
    }
    return "UnknownMAC";
}

// Fungsi sederhana untuk membuat hash dari string (kita gunakan algoritma sederhana untuk demo)
// Untuk produksi, gunakan library hash yang kuat seperti Crypto++ atau Windows CNG API
std::string SimpleHash(const std::string& input) {
    // Ini adalah contoh hash sederhana, bukan kriptografis
    // Untuk produksi, gunakan SHA256 yang sebenarnya
    unsigned long hash = 5381;
    for (char c : input) {
        hash = ((hash << 5) + hash) + c; // hash * 33 + c
    }

    std::stringstream ss;
    ss << std::hex << hash;
    return ss.str();
}

// Fungsi untuk menghasilkan HWID
std::string GenerateHWID() {
    // --- PERIKSA CACHE TERLEBIH DAHULU ---
    if (!g_cachedHWID.empty()) {
        return g_cachedHWID;
    }
    // -------------------------------------

    std::string cpuId = GetCPUID();
    std::string diskSerial = GetDiskSerial();
    std::string macAddress = GetMACAddress();

    // Gabungkan semua informasi
    std::string rawHwid = cpuId + diskSerial + macAddress;

    // Buat hash dari gabungan informasi
    std::string hwidHash = SimpleHash(rawHwid);

    Logger::Log(LOG_INFO, "Raw HWID Components - CPU: " + cpuId + ", Disk: " + diskSerial + ", MAC: " + macAddress);

    // --- CACHE HASILNYA ---
    g_cachedHWID = hwidHash;
    // ----------------------
    return g_cachedHWID;
}

// Fungsi untuk mencatat HWID ke log
void LogHWID() {
    std::string hwid = GenerateHWID();
    Logger::Log(LOG_INFO, "Generated HWID: " + hwid);
}