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
#include <windows.h>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <algorithm>

namespace OblivionEye {

    static std::wstring ToLowerW(const std::wstring& s) { std::wstring r=s; std::transform(r.begin(), r.end(), r.begin(), ::towlower); return r; }
    static std::vector<std::string> SplitLines(const std::string& content) { std::vector<std::string> lines; std::stringstream ss(content); std::string line; while (std::getline(ss,line)) { if(!line.empty()&&line.back()=='\r') line.pop_back(); lines.push_back(line);} return lines; }

    static std::string WToUtf8(const std::wstring& w) {
        int len = WideCharToMultiByte(CP_UTF8,0,w.c_str(),-1,nullptr,0,nullptr,nullptr); std::string s(len,'\0'); WideCharToMultiByte(CP_UTF8,0,w.c_str(),-1,&s[0],len,nullptr,nullptr); if(!s.empty()&&s.back()=='\0') s.pop_back(); return s;
    }

    bool PolicyManager::LoadPolicy(const std::wstring& path) {
        std::ifstream f(path, std::ios::binary); if(!f) return false;
        std::string data((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        auto lines = SplitLines(data);
        enum Section { NONE, PROC, MOD, DRV, OVT, OVC, PUB, PROLOG, CHUNKWL } sec = NONE;
        ClearBlacklistedProcessNames(); ClearBlacklistedModuleNames(); ClearBlacklistedDriverNames(); ClearOverlayTitleBlacklist(); ClearOverlayClassBlacklist(); PublisherWhitelist::Clear(); IntegrityChunkWhitelist::Clear();
        for (auto& raw : lines) {
            std::string line = raw; if(line.empty()||line[0]=='#') continue;
            if (line[0]=='[') { if(line=="[process]")sec=PROC; else if(line=="[module]")sec=MOD; else if(line=="[driver]")sec=DRV; else if(line=="[overlay_title]")sec=OVT; else if(line=="[overlay_class]")sec=OVC; else if(line=="[publisher]")sec=PUB; else if(line=="[prolog]")sec=PROLOG; else if(line=="[chunk_whitelist]")sec=CHUNKWL; else sec=NONE; continue; }
            int wlen = MultiByteToWideChar(CP_UTF8,0,line.c_str(),-1,nullptr,0); std::wstring wline(wlen,L'\0'); MultiByteToWideChar(CP_UTF8,0,line.c_str(),-1,&wline[0],wlen); if(!wline.empty()&&wline.back()==L'\0') wline.pop_back(); wline=ToLowerW(wline); if(wline.empty()) continue;
            switch (sec) {
            case PROC: AddBlacklistedProcessName(wline); break; case MOD: AddBlacklistedModuleName(wline); break; case DRV: AddBlacklistedDriverName(wline); break; case OVT: AddBlacklistedWindowTitle(wline); break; case OVC: AddBlacklistedWindowClass(wline); break; case PUB: PublisherWhitelist::AddTrusted(wline); break; case PROLOG: { std::wstringstream ws(wline); std::wstring mod, fn; unsigned bytes=8; ws>>mod>>fn>>bytes; if(!mod.empty()&&!fn.empty()){ std::string narrow = WToUtf8(fn); PrologHookChecker::Instance().AddTarget(mod,narrow,bytes);} } break; case CHUNKWL: { std::wstringstream ws(wline); std::wstring mod; size_t idx; ws>>mod>>idx; if(!mod.empty()) IntegrityChunkWhitelist::Add(mod, idx); } break; default: break; }
        }
        PrologHookChecker::Instance().Rebaseline(); Log(L"Policy loaded from "+path); return true;
    }

    bool PolicyManager::SavePolicy(const std::wstring& path) {
        std::ofstream f(path, std::ios::binary|std::ios::trunc); if(!f) return false; auto writeSection=[&](const char* n){ f<<n<<"\n"; };
        auto writeList=[&](const std::vector<std::wstring>& list){ for(auto& w: list) f<<WToUtf8(w)<<"\n"; };
        writeSection("[process]"); writeList(GetBlacklistedProcessNames());
        writeSection("[module]"); writeList(GetBlacklistedModuleNames());
        writeSection("[driver]"); writeList(GetBlacklistedDriverNames());
        writeSection("[overlay_title]"); writeList(GetBlacklistedWindowTitles());
        writeSection("[overlay_class]"); writeList(GetBlacklistedWindowClasses());
        writeSection("[publisher]"); writeList(PublisherWhitelist::GetTrusted());
        writeSection("[prolog]"); for (auto& t : PrologHookChecker::Instance().GetTargets()) { f << WToUtf8(t.module) << ' ' << t.function << ' ' << t.minBytes << "\n"; }
        writeSection("[chunk_whitelist]"); for (auto& p : IntegrityChunkWhitelist::GetAll()) { f << WToUtf8(p.first) << ' ' << p.second << "\n"; }
        f.flush(); return true;
    }
}
