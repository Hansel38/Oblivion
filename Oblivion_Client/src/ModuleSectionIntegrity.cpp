#include "../include/ModuleSectionIntegrity.h"
#include "../include/Config.h"
#include "../include/Logger.h"
#include "../include/EventReporter.h"
#include <algorithm>
#include <sstream>


ModuleSectionIntegrity &ModuleSectionIntegrity::Instance(){ static ModuleSectionIntegrity s; return s; }

unsigned long ModuleSectionIntegrity::HashBytes(const unsigned char *data, size_t len) const {
    // Simple Fowler–Noll–Vo variant (not cryptographic, only tamper signal for now)
    unsigned long h = 2166136261u;
    for(size_t i=0;i<len;++i){ h ^= data[i]; h *= 16777619u; }
    return h;
}

bool ModuleSectionIntegrity::ReadSectionBytes(HMODULE hMod, const SectionInfo &sec, std::vector<unsigned char> &out) const {
    const unsigned char *base = reinterpret_cast<const unsigned char*>(hMod);
    const unsigned char *start = base + sec.rva;
    // Clamp sizeRaw against some sanity (avoid overread)
    if(sec.sizeRaw==0 || sec.sizeRaw > 16*1024*1024) return false;
    out.assign(start, start + sec.sizeRaw);
    return true;
}

void ModuleSectionIntegrity::CaptureForModule(ModuleInfo &mod, HMODULE hMod) {
    if(mod.baselineCaptured) return;
    const unsigned char *base = reinterpret_cast<const unsigned char*>(hMod);
    const IMAGE_DOS_HEADER *dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if(dos->e_magic != IMAGE_DOS_SIGNATURE) return;
    const IMAGE_NT_HEADERS *nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if(nt->Signature != IMAGE_NT_SIGNATURE) return;
    const IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    unsigned count = std::min<unsigned>(nt->FileHeader.NumberOfSections, OblivionEye::Config::MEM_SEC_MAX_SECTIONS);
    for(unsigned i=0;i<count;++i){
        SectionInfo si; char nameA[9] = {0}; memcpy(nameA, sec[i].Name, 8); std::wstring wname; for(int k=0;k<8 && nameA[k]; ++k) wname.push_back((wchar_t)tolower(nameA[k])); si.name=wname;
        si.rva = sec[i].VirtualAddress; si.sizeRaw = sec[i].Misc.VirtualSize ? sec[i].Misc.VirtualSize : sec[i].SizeOfRawData;
        std::vector<unsigned char> bytes; if(ReadSectionBytes(hMod, si, bytes)) si.hash = HashBytes(bytes.data(), bytes.size());
        mod.baseline.push_back(si);
    }
    mod.baselineCaptured = true;
    std::wstringstream ws; ws << L"ModuleSectionIntegrity baseline captured for "<< mod.name << L" sections="<< mod.baseline.size();
    OblivionEye::Log(ws.str());
    // Emit structured event baseline summary
    std::wstringstream ev; ev<<L"mod="<<mod.name<<L" sections="<<mod.baseline.size();
    OblivionEye::EventReporter::SendDetection(L"ModuleSectionIntegrity", L"BASELINE " + ev.str());
}

void ModuleSectionIntegrity::CheckModule(ModuleInfo &mod, HMODULE hMod) {
    if(!mod.baselineCaptured) return;
    const unsigned char *base = reinterpret_cast<const unsigned char*>(hMod);
    const IMAGE_DOS_HEADER *dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if(dos->e_magic != IMAGE_DOS_SIGNATURE) return;
    const IMAGE_NT_HEADERS *nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    const IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    // Build current map name->hash for baseline sections only
    std::unordered_map<std::wstring, unsigned long> current;
    for(auto &bsec : mod.baseline){
        // Find matching section by name
        for(unsigned i=0;i<nt->FileHeader.NumberOfSections; ++i){ char nameA[9]={0}; memcpy(nameA, sec[i].Name,8); std::wstring wname; for(int k=0;k<8 && nameA[k]; ++k) wname.push_back((wchar_t)tolower(nameA[k])); if(wname==bsec.name){
                SectionInfo si; si.name=wname; si.rva=sec[i].VirtualAddress; si.sizeRaw=sec[i].Misc.VirtualSize?sec[i].Misc.VirtualSize:sec[i].SizeOfRawData; std::vector<unsigned char> bytes; if(ReadSectionBytes(hMod, si, bytes)) current[wname]=HashBytes(bytes.data(), bytes.size());
            }
        }
    }
    std::wstring deltas; bool mismatch=false;
    for(auto &bsec : mod.baseline){ auto it=current.find(bsec.name); if(it==current.end()) { mismatch=true; deltas += L"[missing:"+bsec.name+L"]"; }
        else if(it->second != bsec.hash) { mismatch=true; deltas += L"[diff:"+bsec.name+L"]"; }
    }
    if(mismatch && !mod.mismatchReported){
        mod.mismatchReported = true;
    OblivionEye::EventReporter::SendDetection(L"ModuleSectionIntegrity", L"MISMATCH mod="+mod.name+L" deltas="+deltas);
    OblivionEye::Log(L"Module section integrity mismatch " + mod.name + L" " + deltas); // Replaced ShowDetectionAndExit (not available) with logging
    }
}

void ModuleSectionIntegrity::EnsureBaseline() {
    // Target modules list
    std::vector<std::wstring> mods = {L"ntdll.dll", L"kernel32.dll", L"user32.dll"};
    for(auto &m : mods){ std::wstring key = m; std::transform(key.begin(), key.end(), key.begin(), ::towlower); if(!m_modules.count(key)) { ModuleInfo mi; mi.name=key; m_modules[key]=mi; } }
    // Attempt capture for each
    for(auto &kv : m_modules){ HMODULE h = GetModuleHandleW(kv.first.c_str()); if(h) CaptureForModule(kv.second, h); }
}

void ModuleSectionIntegrity::Tick() {
    unsigned long now = GetTickCount();
    if(now - m_lastCheckTick < OblivionEye::Config::MEM_SEC_INTEGRITY_INTERVAL_MS) return;
    m_lastCheckTick = now;
    EnsureBaseline();
    // After baseline captured, run check
    for(auto &kv : m_modules){ HMODULE h = GetModuleHandleW(kv.first.c_str()); if(h) CheckModule(kv.second, h); }
}
