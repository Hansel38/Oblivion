#include "../pch.h"
#include "../include/SignatureScanner.h"
#include "../include/Signatures.h"
#include "../include/Logger.h"
#include "../include/Utils.h"
#include "../include/EventReporter.h"
#include <windows.h>
#include <psapi.h>
#include <vector>
#include <string>
#include <thread>
#include <chrono>

#pragma comment(lib, "psapi.lib")

namespace OblivionEye {

    static bool MatchAt(const uint8_t* data, size_t size, const BytePattern& pat) {
        if (size < pat.bytes.size()) return false;
        for (size_t i = 0; i < pat.bytes.size(); ++i) {
            if (pat.mask[i] && data[i] != pat.bytes[i]) return false;
        }
        return true;
    }

    static bool ScanBuffer(const uint8_t* data, size_t size, const BytePattern& pat) {
        if (pat.bytes.empty()) return false;
        size_t maxSize = size > (16 * 1024 * 1024) ? (16 * 1024 * 1024) : size;
        for (size_t i = 0; i + pat.bytes.size() <= maxSize; ++i) {
            if (MatchAt(data + i, maxSize - i, pat)) return true;
        }
        return false;
    }

    SignatureScanner& SignatureScanner::Instance() { static SignatureScanner s; return s; }

    bool SignatureScanner::ScanModule(HMODULE hMod, const wchar_t* modName) {
        MODULEINFO mi{};
        if (!GetModuleInformation(GetCurrentProcess(), hMod, &mi, sizeof(mi))) return false;
        auto base = reinterpret_cast<uint8_t*>(mi.lpBaseOfDll);
        size_t size = static_cast<size_t>(mi.SizeOfImage);
        const auto& sigs = GetSignatures();
        for (const auto& sig : sigs) {
            if (ScanBuffer(base, size, sig)) {
                EventReporter::SendDetection(L"SignatureScanner", sig.name + L" in " + modName);
                ShowDetectionAndExit(L"Signature match: " + sig.name + L" in " + modName);
                return true;
            }
        }
        return false;
    }

    bool SignatureScanner::ScanMemory() {
        HMODULE mods[1024] = {};
        DWORD needed = 0;
        if (!EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &needed)) return false;
        int count = needed / sizeof(HMODULE);
        wchar_t name[MAX_PATH];
        for (int i = 0; i < count; ++i) {
            if (GetModuleBaseNameW(GetCurrentProcess(), mods[i], name, MAX_PATH)) {
                if (ScanModule(mods[i], name)) return true;
            }
        }
        return false;
    }

    void SignatureScanner::Start(unsigned intervalMs) {
        if (m_running.exchange(true)) return;
        std::thread([this, intervalMs]() { Loop(intervalMs); }).detach();
    }

    void SignatureScanner::Stop() { m_running = false; }

    void SignatureScanner::Loop(unsigned intervalMs) {
        Log(L"SignatureScanner start");
        while (m_running) {
            if (ScanMemory()) return; 
            std::this_thread::sleep_for(std::chrono::milliseconds(intervalMs));
        }
        Log(L"SignatureScanner stop");
    }
}
