#include "../include/memory_scanner.h"
#include <Windows.h>
#include <vector>
#include <string>
#include <algorithm>
#include <exception>

namespace MemoryScanner {
    // Struktur untuk definisi signature
    struct SignatureDefinition {
        const BYTE* signature;
        const char* mask;
        SIZE_T length;
        const char* description;
    };

    // Daftar signature cheat engine dan tool terkait
    const SignatureDefinition CHEAT_SIGNATURES[] = {
        {
            (const BYTE*)"\x55\x8B\xEC\x83\xEC\x28\x53\x56\x57",
            "xxxxxxxxx",
            9,
            "Cheat Engine Code Pattern"
        },
        {
            (const BYTE*)"\x43\x68\x65\x61\x74\x20\x45\x6E\x67\x69\x6E\x65\x20\x41\x63\x63\x65\x6C\x65\x72\x61\x74\x6F\x72",
            "xxxxxxxxxxxxxxxxxxxxxxx",
            23,
            "Cheat Engine Accelerator"
        },
        {
            (const BYTE*)"\x43\x68\x65\x61\x74\x45\x6E\x67\x69\x6E\x65\x5F\x44\x65\x62\x75\x67\x67\x65\x72",
            "xxxxxxxxxxxxxxxxxxxx",
            20,
            "Cheat Engine Debugger"
        }
    };

    // Daftar region memori yang diizinkan (whitelist)
    std::vector<std::pair<BYTE*, SIZE_T>> WHITELISTED_REGIONS;

    void AddToWhitelist(BYTE* baseAddress, SIZE_T regionSize) {
        WHITELISTED_REGIONS.push_back(std::make_pair(baseAddress, regionSize));
    }

    bool IsRegionWhitelisted(const BYTE* address) {
        for (const auto& region : WHITELISTED_REGIONS) {
            if (address >= region.first && address < region.first + region.second) {
                return true;
            }
        }
        return false;
    }

    bool ScanRegionForSignature(const BYTE* startAddress, SIZE_T regionSize, const BYTE* signature, const char* mask, SIZE_T signatureLength) {
        if (regionSize < signatureLength || signatureLength == 0) {
            return false;
        }

        for (SIZE_T i = 0; i < regionSize - signatureLength; i++) {
            bool found = true;
            for (SIZE_T j = 0; j < signatureLength; j++) {
                if (mask[j] != '?' && startAddress[i + j] != signature[j]) {
                    found = false;
                    break;
                }
            }
            if (found) {
                return true;
            }
        }
        return false;
    }

    bool ScanMemoryForSignatures() {
        try {
            SYSTEM_INFO sysInfo;
            GetSystemInfo(&sysInfo);

            BYTE* addr = (BYTE*)sysInfo.lpMinimumApplicationAddress;
            BYTE* end = (BYTE*)sysInfo.lpMaximumApplicationAddress;

            MEMORY_BASIC_INFORMATION memInfo;

            while (addr < end) {
                if (VirtualQuery(addr, &memInfo, sizeof(memInfo)) == 0) {
                    addr += 0x1000;
                    continue;
                }

                if (memInfo.RegionSize == 0) {
                    addr += 0x1000;
                    continue;
                }

                if ((memInfo.State == MEM_COMMIT) &&
                    (memInfo.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {

                    if (IsRegionWhitelisted((BYTE*)memInfo.BaseAddress)) {
                        addr += memInfo.RegionSize;
                        continue;
                    }

                    for (const auto& sig : CHEAT_SIGNATURES) {
                        if (ScanRegionForSignature((BYTE*)memInfo.BaseAddress, memInfo.RegionSize, sig.signature, sig.mask, sig.length)) {
                            return true;
                        }
                    }
                }

                addr += memInfo.RegionSize;
            }
        }
        catch (...) {
            return false;
        }

        return false;
    }
}