#include "../include/HWIDSystem.h"
#include "../include/Logger.h"
#include <windows.h>
#include <intrin.h>
#include <iphlpapi.h>
#include <iomanip>
#include <sstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <array>
#include <algorithm>

#pragma comment(lib, "iphlpapi.lib")

// Helper: Eksekusi command line dan ambil output
static std::string ExecCommand(const char* cmd) {
    Logger::Log("[HWID] Executing: " + std::string(cmd));

    // Coba eksekusi command
    FILE* pipe = _popen(cmd, "r");
    if (!pipe) {
        Logger::Log("[HWID] Failed to execute command (pipe failed)");
        return "";
    }

    char buffer[128];
    std::string result = "";
    while (fgets(buffer, sizeof buffer, pipe) != nullptr) {
        result += buffer;
    }

    int res = _pclose(pipe);
    Logger::Log("[HWID] Command result: " + result);
    Logger::Log("[HWID] _pclose result: " + std::to_string(res));

    return result;
}

// 1. Dapatkan CPU ID
std::string HWIDSystem::GetCPUID() {
    Logger::Log("[HWID] Getting CPU ID...");
    try {
        int cpuInfo[4] = { 0 };
        __cpuid(cpuInfo, 0);

        std::stringstream ss;
        ss << std::hex << std::uppercase << std::setfill('0');
        for (int i = 0; i < 4; i++) {
            ss << std::setw(8) << cpuInfo[i];
        }
        std::string cpuID = ss.str();
        Logger::Log("[HWID] CPU ID Result: " + cpuID);
        return cpuID;
    }
    catch (...) {
        Logger::Log("[HWID] Error getting CPU ID");
        return "CPU_ERROR";
    }
}

// 2. Dapatkan Disk Serial
std::string HWIDSystem::GetDiskSerial() {
    Logger::Log("[HWID] Getting Disk Serial...");
    try {
        std::string cmd = "wmic diskdrive get serialnumber | findstr /R \"[0-9A-Za-z]\"";
        std::string result = ExecCommand(cmd.c_str());

        if (!result.empty()) {
            // Bersihkan
            result.erase(std::remove(result.begin(), result.end(), '\n'), result.end());
            result.erase(std::remove(result.begin(), result.end(), '\r'), result.end());
            result.erase(0, result.find_first_not_of(' '));
            result.erase(result.find_last_not_of(' ') + 1);

            if (!result.empty()) {
                Logger::Log("[HWID] Disk Serial Found: " + result);
                return result;
            }
        }
        Logger::Log("[HWID] Disk Serial Empty or Not Found");
        return "DISK_UNKNOWN";
    }
    catch (...) {
        Logger::Log("[HWID] Error getting Disk Serial");
        return "DISK_ERROR";
    }
}

// 3. Dapatkan MAC Address
std::string HWIDSystem::GetMACAddress() {
    Logger::Log("[HWID] Getting MAC Address...");
    try {
        PIP_ADAPTER_INFO pAdapterInfo;
        PIP_ADAPTER_INFO pAdapter = NULL;
        DWORD dwRetVal = 0;
        ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);

        pAdapterInfo = (IP_ADAPTER_INFO*)malloc(sizeof(IP_ADAPTER_INFO));
        if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
            free(pAdapterInfo);
            pAdapterInfo = (IP_ADAPTER_INFO*)malloc(ulOutBufLen);
        }

        if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR) {
            pAdapter = pAdapterInfo;
            while (pAdapter) {
                if (pAdapter->Type == MIB_IF_TYPE_ETHERNET && pAdapter->AddressLength == 6) {
                    std::stringstream ss;
                    for (UINT i = 0; i < pAdapter->AddressLength; i++) {
                        ss << std::hex << std::uppercase << std::setfill('0') << std::setw(2) << (int)pAdapter->Address[i];
                        if (i < pAdapter->AddressLength - 1) ss << "-";
                    }
                    std::string mac = ss.str();
                    Logger::Log("[HWID] MAC Found: " + mac);
                    free(pAdapterInfo);
                    return mac;
                }
                pAdapter = pAdapter->Next;
            }
        }

        if (pAdapterInfo) free(pAdapterInfo);
        Logger::Log("[HWID] MAC Address Not Found");
        return "MAC_UNKNOWN";
    }
    catch (...) {
        Logger::Log("[HWID] Error getting MAC Address");
        return "MAC_ERROR";
    }
}

// 4. Hash string
std::string HWIDSystem::HashString(const std::string& str) {
    Logger::Log("[HWID] Hashing string (length: " + std::to_string(str.length()) + ")");
    try {
        std::hash<std::string> hasher;
        size_t hash = hasher(str);
        std::stringstream ss;
        ss << std::hex << hash;
        std::string hashed = ss.str();
        Logger::Log("[HWID] Hash Result: " + hashed);
        return hashed;
    }
    catch (...) {
        Logger::Log("[HWID] Error hashing string");
        return "HASH_ERROR";
    }
}

// Fungsi utama
std::string HWIDSystem::GenerateHWID() {
    Logger::Log("[HWID] === GenerateHWID Started ===");

    std::string cpuID = GetCPUID();
    std::string diskSerial = GetDiskSerial();
    std::string macAddress = GetMACAddress();

    std::string rawHWID = cpuID + "|" + diskSerial + "|" + macAddress; // Tambahkan separator
    Logger::Log("[HWID] Raw HWID: " + rawHWID);

    std::string hashedHWID = HashString(rawHWID);

    Logger::Log("[HWID] Final HWID: " + hashedHWID);
    Logger::Log("[HWID] === GenerateHWID Completed ===");
    return hashedHWID;
}