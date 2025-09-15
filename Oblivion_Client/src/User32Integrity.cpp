#include "../pch.h"
#include "../include/User32Integrity.h"
#include "../include/Logger.h"
#include "../include/EventReporter.h"
#include "../include/Utils.h"
#include "../include/IntegrityChunkWhitelist.h"
#include "../include/Config.h"
#include <windows.h>
#include <sstream>
#include <iomanip>

namespace OblivionEye {
namespace {
    unsigned long long Fnv1a64(const unsigned char *d, size_t l) {
        const unsigned long long O = 1469598103934665603ULL;
        const unsigned long long P = 1099511628211ULL;
        unsigned long long h = O;
        for (size_t i = 0; i < l; ++i) { h ^= d[i]; h *= P; }
        return h;
    }

    std::wstring Hex64(uint64_t v) {
        std::wstringstream ss; ss << std::hex << std::setw(8) << std::setfill(L'0') << v; return ss.str();
    }

    bool GetModuleTextRegion(const wchar_t *mod, unsigned char *&b, size_t &s) {
        HMODULE h = GetModuleHandleW(mod); if (!h) return false;
        auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(h); if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
        auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<unsigned char*>(h) + dos->e_lfanew); if (!nt || nt->Signature != IMAGE_NT_SIGNATURE) return false;
        auto sec = IMAGE_FIRST_SECTION(nt);
        for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
            const char *name = reinterpret_cast<const char*>(sec[i].Name);
            if (strncmp(name, ".text", 5) == 0) {
                b = reinterpret_cast<unsigned char*>(h) + sec[i].VirtualAddress;
                s = sec[i].Misc.VirtualSize ? sec[i].Misc.VirtualSize : sec[i].SizeOfRawData;
                return true;
            }
        }
        return false;
    }
}

User32Integrity &User32Integrity::Instance() { static User32Integrity s; return s; }

bool User32Integrity::CaptureSubsectionHashes() {
    unsigned char *base = nullptr; size_t size = 0;
    if (!GetModuleTextRegion(L"user32.dll", base, size)) return false;
    const size_t chunk = OblivionEye::Config::CHUNK_SIZE; size_t n = (size + chunk - 1) / chunk;
    m_chunkHashes.resize(n);
    for (size_t i = 0; i < n; ++i) {
        size_t off = i * chunk;
        size_t len = (off + chunk <= size) ? chunk : (size - off);
        m_chunkHashes[i] = Fnv1a64(base + off, len);
    }
    return true;
}

void User32Integrity::CaptureBaseline() {
    if (m_baselineCaptured) return;
    unsigned char *base = nullptr; size_t size = 0;
    if (!GetModuleTextRegion(L"user32.dll", base, size)) return;
    m_baselineHash = Fnv1a64(base, size);
    CaptureSubsectionHashes();
    m_baselineCaptured = true;
    Log(L"User32Integrity baseline captured");
}

bool User32Integrity::Check() {
    unsigned char *base = nullptr; size_t size = 0;
    if (!GetModuleTextRegion(L"user32.dll", base, size)) return false;
    auto current = Fnv1a64(base, size);

    if (!m_baselineCaptured || current == m_baselineHash)
        return false;

    const size_t chunk = OblivionEye::Config::CHUNK_SIZE; size_t n = (size + chunk - 1) / chunk;
    std::wstring delta;
    for (size_t i = 0; i < n && i < m_chunkHashes.size(); ++i) {
        size_t off = i * chunk;
        size_t len = (off + chunk <= size) ? chunk : (size - off);
        unsigned long long h = Fnv1a64(base + off, len);
        if (h != m_chunkHashes[i]) {
            if (IntegrityChunkWhitelist::IsWhitelisted(L"user32.dll", i))
                continue;
            delta += L"[" + std::to_wstring(i) + L"@0x" + Hex64(static_cast<uint64_t>(off)) + L"]";
        }
    }

    if (delta.empty())
        return false;

    EventReporter::SendDetection(L"User32Integrity", L"user32 .text modified chunks:" + delta);
    ShowDetectionAndExit(L"user32 integrity mismatch " + delta);
    return true;
}

void User32Integrity::Tick() { if (!m_baselineCaptured) CaptureBaseline(); else Check(); }
}
