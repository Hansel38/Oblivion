#include "../pch.h"
#include <unordered_set>
#include "../include/SignatureScanner.h"
#include "../include/Config.h"
#include "../include/Signatures.h"
#include "../include/Logger.h"
#include "../include/Utils.h"
#include "../include/EventReporter.h"
#include "../include/DetectionCorrelator.h"
#include <windows.h>
#include <psapi.h>
#include <vector>
#include <string>

#pragma comment(lib, "psapi.lib")

namespace OblivionEye {
namespace {
    bool MatchAt(const uint8_t *data, size_t size, const BytePattern &pat) {
        if (size < pat.bytes.size()) return false;
        for (size_t i = 0; i < pat.bytes.size(); ++i) {
            if (pat.mask[i] && data[i] != pat.bytes[i]) return false;
        }
        return true;
    }

    bool ScanBuffer(const uint8_t *data, size_t size, const BytePattern &pat) {
        if (pat.bytes.empty()) return false;
    size_t maxSize = size > OblivionEye::Config::SIGNATURE_SCAN_MAX ? OblivionEye::Config::SIGNATURE_SCAN_MAX : size; // cap scan size
        for (size_t i = 0; i + pat.bytes.size() <= maxSize; ++i) {
            if (MatchAt(data + i, maxSize - i, pat)) return true;
        }
        return false;
    }
}

SignatureScanner &SignatureScanner::Instance() { static SignatureScanner s; return s; }

bool SignatureScanner::ScanModule(HMODULE hMod, const wchar_t *modName) {
    MODULEINFO mi{};
    if (!GetModuleInformation(GetCurrentProcess(), hMod, &mi, sizeof(mi))) {
        Log(L"SignatureScanner: GetModuleInformation gagal untuk " + std::wstring(modName));
        return false;
    }
    auto base = reinterpret_cast<uint8_t*>(mi.lpBaseOfDll);
    size_t size = static_cast<size_t>(mi.SizeOfImage);

    const auto &sigs = GetSignatures();
    bool firstHit = false;
    bool anyFull = false;
    // Heuristic assumption: signature[0] = UI/string cluster, signature[1+] may include exec stubs.
    for (size_t idx=0; idx<sigs.size(); ++idx) {
        const auto &sig = sigs[idx];
        if (ScanBuffer(base, size, sig)) {
            if (idx==0) {
                firstHit = true; // possible partial
                continue; // don't instantly treat as full until we see stronger pattern
            }
            // Any non-zero index considered strong/full match → escalate
            anyFull = true;
            EventReporter::SendDetection(L"SignatureScanner", sig.name + L" in " + modName);
            ShowDetectionAndExit(L"Signature match: " + sig.name + L" in " + modName);
            return true;
        }
    }
    // Emit partial only if we saw UI/string cluster (idx0) but no full signature.
    if (firstHit && !anyFull) {
        // Correlator partial event (weight SIG_PARTIAL_SCORE); avoid spamming by only sending once per module per scan.
        static std::unordered_set<std::wstring> reportedModules; // session lifetime OK
        if (reportedModules.insert(modName).second) {
            DetectionCorrelator::Instance().Report(L"SIG_PARTIAL", std::wstring(L"UICluster in ")+modName, Config::SIG_PARTIAL_SCORE);
            Log(L"SignatureScanner partial (UI cluster) in "+std::wstring(modName));
        }
    }
    return false;
}

bool SignatureScanner::ScanMemory() {
    HMODULE mods[OblivionEye::Config::MODULE_ENUM_MAX] = {}; DWORD needed = 0;
    if (!EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &needed)) {
        Log(L"SignatureScanner: EnumProcessModules gagal");
        return false;
    }
    int count = static_cast<int>(needed / sizeof(HMODULE));
    wchar_t name[MAX_PATH];
    for (int i = 0; i < count; ++i) {
        if (GetModuleBaseNameW(GetCurrentProcess(), mods[i], name, MAX_PATH)) {
            if (ScanModule(mods[i], name)) return true;
        }
    }
    return false;
}

void SignatureScanner::Tick() { ScanMemory(); }
}
