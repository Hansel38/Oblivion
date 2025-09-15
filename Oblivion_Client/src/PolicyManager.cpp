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
                std::wstringstream ws(wline); std::wstring mod; size_t idx; ws >> mod >> idx;
                if (!mod.empty()) IntegrityChunkWhitelist::Add(mod, idx);
            } break;
            case INTERVAL: {
                std::wstringstream ws(wline); std::wstring name; unsigned val = 0; ws >> name >> val;
                if (!name.empty() && val > 0) DetectorScheduler::Instance().SetIntervalOverride(name, val);
            } break;
            case SIG: {
                // format: <name>|<pattern hex with ??> (nama: case dipertahankan)
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
