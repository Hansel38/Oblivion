#pragma once
#include <vector>
#include <string>
#include <unordered_map>
#include <windows.h>

// ModuleSectionIntegrity: Baselines PE executable section hashes of critical modules and periodically re-validates.
// Emits events via EventReporter when mismatches are detected.
// Phase 1 scope: ntdll.dll, kernel32.dll, user32.dll (.text, .rdata, .data sections up to MEM_SEC_MAX_SECTIONS)

class ModuleSectionIntegrity {
public:
    static ModuleSectionIntegrity &Instance();
    void Tick();
private:
    ModuleSectionIntegrity() = default;
    ModuleSectionIntegrity(const ModuleSectionIntegrity&) = delete;
    ModuleSectionIntegrity& operator=(const ModuleSectionIntegrity&) = delete;

    struct SectionInfo {
        std::wstring name;         // section name (wide)
        unsigned long rva = 0;     // RVA
        unsigned long sizeRaw = 0; // Raw size
        unsigned long hash = 0;    // Simple 32-bit rolling hash (phase1) or truncated digests
    };
    struct ModuleInfo {
        std::wstring name; // lowercase filename
        std::vector<SectionInfo> baseline;
        bool baselineCaptured = false;
        bool mismatchReported = false; // avoid spam
    };

    std::unordered_map<std::wstring, ModuleInfo> m_modules; // key: module filename lowercase
    unsigned long m_lastCheckTick = 0;

    void EnsureBaseline();
    void CaptureForModule(ModuleInfo &mod, HMODULE hMod);
    void CheckModule(ModuleInfo &mod, HMODULE hMod);
    unsigned long HashBytes(const unsigned char *data, size_t len) const;
    bool ReadSectionBytes(HMODULE hMod, const SectionInfo &sec, std::vector<unsigned char> &out) const;
};
