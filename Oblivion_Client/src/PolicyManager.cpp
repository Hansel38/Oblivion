#include "../pch.h"
#include "../include/PolicyManager.h"
#include "../include/Blacklist.h"
#include "../include/ModuleBlacklist.h"
#include "../include/DriverBlacklist.h"
#include "../include/OverlayBlacklist.h"
#include "../include/PrologHookChecker.h"
#include "../include/PublisherWhitelist.h"
#include "../include/Logger.h"
#include "../include/IntegrityChunkWhitelist.h"
#include "../include/EmbeddedPolicy.h"
#include "../include/DetectorScheduler.h"
#include "../include/Signatures.h"
#include <windows.h>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <algorithm>
#include "../include/StringUtil.h"
#include <limits> // untuk std::numeric_limits<size_t>

namespace OblivionEye {
namespace {
    std::wstring ToLowerCopy(const std::wstring &s) { std::wstring r = s; std::transform(r.begin(), r.end(), r.begin(), ::towlower); return r; }

    std::vector<std::string> SplitLines(const std::string &content) {
        std::vector<std::string> lines; std::stringstream ss(content); std::string line;
        while (std::getline(ss, line)) { if (!line.empty() && line.back() == '\r') line.pop_back(); lines.push_back(line); }
        return lines;
    }

    using OblivionEye::StringUtil::WideToUtf8;

    std::wstring Utf8ToLowerW(const std::string &line) {
        auto w = OblivionEye::StringUtil::Utf8ToWide(line);
        return ToLowerCopy(w);
    }

    void ParsePolicyContent(const std::string &data) {
    enum Section { NONE, PROC, MOD, DRV, OVT, OVC, PUB, PROLOG, CHUNKWL, INTERVAL, SIG } sec = NONE;

        // Reset existing lists before parsing
        ClearBlacklistedProcessNames();
        ClearBlacklistedModuleNames();
        ClearBlacklistedDriverNames();
        ClearOverlayTitleBlacklist();
        ClearOverlayClassBlacklist();
        PublisherWhitelist::Clear();
        IntegrityChunkWhitelist::Clear();

        for (const auto &raw : SplitLines(data)) {
            if (raw.empty() || raw[0] == '#')
                continue;
            if (raw[0] == '[') {
                if (raw == "[process]") sec = PROC; else if (raw == "[module]") sec = MOD; else if (raw == "[driver]") sec = DRV;
                else if (raw == "[overlay_title]") sec = OVT; else if (raw == "[overlay_class]") sec = OVC; else if (raw == "[publisher]") sec = PUB;
                else if (raw == "[prolog]") sec = PROLOG; else if (raw == "[chunk_whitelist]") sec = CHUNKWL; else if (raw == "[interval]") sec = INTERVAL;
                else if (raw == "[signature]") { sec = SIG; ::OblivionEye::ClearSignatures(); }
                else sec = NONE;
                continue;
            }
            // Simpan original wide untuk nama (khusus signature); lowercase copy untuk section lain.
            auto worig = OblivionEye::StringUtil::Utf8ToWide(raw);
            auto wline = Utf8ToLowerW(raw);
            if (wline.empty()) continue;

            switch (sec) {
            case PROC: AddBlacklistedProcessName(wline); break;
            case MOD: AddBlacklistedModuleName(wline); break;
            case DRV: AddBlacklistedDriverName(wline); break;
            case OVT: AddBlacklistedWindowTitle(wline); break;
            case OVC: AddBlacklistedWindowClass(wline); break;
            case PUB: PublisherWhitelist::AddTrusted(wline); break;
            case PROLOG: {
                std::wstringstream ws(wline); std::wstring mod, fn; unsigned bytes = 8; ws >> mod >> fn >> bytes;
                if (!mod.empty() && !fn.empty()) {
                    std::string narrow = WideToUtf8(fn);
                    PrologHookChecker::Instance().AddTarget(mod, narrow, bytes);
                }
            } break;
            case CHUNKWL: {
                // Accept forms:
                // 1) module idx            -> module single index
                // 2) module start-end      -> module range
                // 3) m10-15                -> implicit module 'ntdll.dll' (shortcut) example
                // 4) user32.dll:m5-12      -> explicit module:prefix 'mod:' then token
                // 5) ntdll.dll:m7          -> single via mod:m<idx>
                // Backwards compatible with original "mod idx"
                std::wstring mod; std::wstring rest;
                {
                    std::wstringstream ws(wline); ws >> mod; std::getline(ws, rest); // rest may contain index or pattern
                }
                if(mod.empty()) break;
                // Trim leading spaces in rest
                while(!rest.empty() && iswspace(rest.front())) rest.erase(rest.begin());
                if(rest.empty()) break; // need index spec
                auto toLower = [](std::wstring s){ std::transform(s.begin(), s.end(), s.begin(), ::towlower); return s; };
                auto applyRange=[&](const std::wstring &m, size_t a, size_t b){ IntegrityChunkWhitelist::AddRange(toLower(m), a, b); };
                auto applySingle=[&](const std::wstring &m, size_t x){ IntegrityChunkWhitelist::Add(toLower(m), x); };

                // Helper to parse token patterns like m10-15 or m7
                auto parseMToken=[&](const std::wstring &tok, const std::wstring &currentModule){
                    if(tok.size()<2 || (tok[0] != L'm' && tok[0] != L'M')) return false;
                    size_t dash = tok.find(L'-');
                    // Gunakan bentuk parenthesized untuk menghindari konflik macro max dari <windows.h>
                    constexpr size_t maxSize = (std::numeric_limits<size_t>::max)();
                    try {
                        if(dash==std::wstring::npos){
                            unsigned long long v = std::stoull(tok.substr(1));
                            if(v>maxSize) return false; // nilai terlalu besar untuk size_t pada platform ini
                            applySingle(currentModule, static_cast<size_t>(v));
                            return true;
                        } else {
                            unsigned long long va = std::stoull(tok.substr(1, dash-1));
                            unsigned long long vb = std::stoull(tok.substr(dash+1));
                            if(vb>=va && va<=maxSize && vb<=maxSize){
                                applyRange(currentModule, static_cast<size_t>(va), static_cast<size_t>(vb));
                            }
                            return true;
                        }
                    } catch(...) { return false; }
                };

                // Case: token may itself contain ':' -> module override
                if(mod.find(L":") != std::wstring::npos && rest.empty()) {
                    // Example: user32.dll:m10-12 (mod is actually full token)
                    auto colon = mod.find(L":"); std::wstring realMod = mod.substr(0, colon); std::wstring token = mod.substr(colon+1);
                    if(!parseMToken(token, realMod)) {
                        // fallback parse as legacy (should not happen)
                    }
                    break;
                }

                // 'mod rest' path. 'rest' could be numeric, range, or m-token; or mod was actually a shortcut like m10-12 (implicit ntdll)
                if(mod[0]==L'm' || mod[0]==L'M') {
                    // Shortcut: interpret as implicit ntdll.dll (common hot module) unless changed later
                    if(!parseMToken(mod, L"ntdll.dll")) {}
                    break;
                }

                // Now mod is module name; rest may be number, start-end, or mX[-Y]
                if(rest[0]==L'm' || rest[0]==L'M') {
                    // rest adalah m-token
                    parseMToken(rest, mod);
                } else {
                    // parse numeric or range: contoh 10 atau 10-15
                    size_t dash = rest.find(L'-');
                    // Bentuk aman terhadap macro max
                    constexpr size_t maxSize = (std::numeric_limits<size_t>::max)();
                    try {
                        if(dash==std::wstring::npos) {
                            unsigned long long v = std::stoull(rest);
                            if(v<=maxSize) applySingle(mod, static_cast<size_t>(v));
                        } else {
                            unsigned long long va = std::stoull(rest.substr(0,dash));
                            unsigned long long vb = std::stoull(rest.substr(dash+1));
                            if(vb>=va && va<=maxSize && vb<=maxSize) applyRange(mod, static_cast<size_t>(va), static_cast<size_t>(vb));
                        }
                    } catch(...) { /* abaikan baris rusak */ }
                }
            } break;
            case INTERVAL: {
                std::wstringstream ws(wline); std::wstring name; unsigned val = 0; ws >> name >> val;
                if (!name.empty() && val > 0) DetectorScheduler::Instance().SetIntervalOverride(name, val);
            } break;
            case SIG: {
                // format: <name>|<pattern hex dengan ??> (nama: case dipertahankan)
                auto pipePos = worig.find(L"|");
                if (pipePos != std::wstring::npos) {
                    std::wstring nm = worig.substr(0, pipePos); // original case
                    std::wstring patRaw = worig.substr(pipePos + 1);
                    // Lowercase pattern untuk fleksibilitas input hex
                    std::wstring pat = patRaw; std::transform(pat.begin(), pat.end(), pat.begin(), ::towlower);
                    // Trim spasi depan/belakang sederhana
                    while (!nm.empty() && iswspace(nm.front())) nm.erase(nm.begin());
                    while (!nm.empty() && iswspace(nm.back())) nm.pop_back();
                    while (!pat.empty() && iswspace(pat.front())) pat.erase(pat.begin());
                    while (!pat.empty() && iswspace(pat.back())) pat.pop_back();
                    if (!nm.empty() && !pat.empty()) AddSignaturePattern(nm, pat);
                }
            } break;
            default: break;
            }
        }
        PrologHookChecker::Instance().Rebaseline();
    }
}

bool PolicyManager::LoadPolicy(const std::wstring &path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        Log(L"Policy load failed, using embedded fallback");
        ParsePolicyContent(kEmbeddedPolicy);
        return false;
    }
    std::string data((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    ParsePolicyContent(data);
    Log(L"Policy loaded from " + path);
    return true;
}

bool PolicyManager::SavePolicy(const std::wstring &path) {
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) return false;

    auto writeSection = [&](const char *n){ f << n << "\n"; };
    auto writeList = [&](const std::vector<std::wstring> &list){ for (auto &w : list) f << WideToUtf8(w) << "\n"; };

    writeSection("[process]");       writeList(GetBlacklistedProcessNames());
    writeSection("[module]");        writeList(GetBlacklistedModuleNames());
    writeSection("[driver]");        writeList(GetBlacklistedDriverNames());
    writeSection("[overlay_title]"); writeList(GetBlacklistedWindowTitles());
    writeSection("[overlay_class]"); writeList(GetBlacklistedWindowClasses());
    writeSection("[publisher]");     writeList(PublisherWhitelist::GetTrusted());

    writeSection("[prolog]");
    for (auto &t : PrologHookChecker::Instance().GetTargets())
    f << WideToUtf8(t.module) << ' ' << t.function << ' ' << t.minBytes << "\n";

    writeSection("[chunk_whitelist]");
    for (auto &p : IntegrityChunkWhitelist::GetAll())
    f << WideToUtf8(p.first) << ' ' << p.second << "\n";

    auto overrides = DetectorScheduler::Instance().GetIntervalOverrides();
    if (!overrides.empty()) {
        writeSection("[interval]");
        for (auto &kv : overrides)
            f << WideToUtf8(kv.first) << ' ' << kv.second << "\n";
    }

    f.flush();
    return true;
}
}
