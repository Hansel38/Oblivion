#include "../pch.h"
#include "../include/IntegrityChunkWhitelist.h"
#include <algorithm>
#include <vector>

namespace OblivionEye {
namespace IntegrityChunkWhitelist {
    struct Interval { size_t a; size_t b; }; // inclusive
    struct Entry { std::wstring mod; std::vector<Interval> intervals; };
    static std::vector<Entry> g_entries; // per-module merged intervals
    static std::mutex g_mtx;

    static std::wstring ToLower(const std::wstring& s){ std::wstring r=s; std::transform(r.begin(), r.end(), r.begin(), ::towlower); return r; }

    static void MergeIntervals(std::vector<Interval> &iv){ if(iv.empty()) return; std::sort(iv.begin(), iv.end(),[](const Interval&x,const Interval&y){ return x.a<y.a; }); std::vector<Interval> out; out.push_back(iv[0]); for(size_t i=1;i<iv.size();++i){ if(iv[i].a <= out.back().b + 1){ if(iv[i].b>out.back().b) out.back().b=iv[i].b; } else out.push_back(iv[i]); } iv.swap(out); }

    void Add(const std::wstring& moduleNameLower, size_t chunkIndex){ AddRange(moduleNameLower, chunkIndex, chunkIndex); }

    void AddRange(const std::wstring& moduleNameLower, size_t startInclusive, size_t endInclusive){
        if(endInclusive < startInclusive) return; std::lock_guard<std::mutex> lk(g_mtx);
        auto low=ToLower(moduleNameLower);
        for(auto &e : g_entries){ if(e.mod==low){ e.intervals.push_back({startInclusive,endInclusive}); MergeIntervals(e.intervals); return; } }
        Entry e; e.mod=low; e.intervals.push_back({startInclusive,endInclusive}); g_entries.push_back(std::move(e));
    }

    bool IsWhitelisted(const std::wstring& moduleNameLower, size_t chunkIndex){ std::lock_guard<std::mutex> lk(g_mtx); auto low=ToLower(moduleNameLower); for(auto &e: g_entries) if(e.mod==low){ for(auto &iv: e.intervals) if(chunkIndex>=iv.a && chunkIndex<=iv.b) return true; } return false; }

    void Clear(){ std::lock_guard<std::mutex> lk(g_mtx); g_entries.clear(); }

    std::vector<std::pair<std::wstring,size_t>> GetAll(){ std::lock_guard<std::mutex> lk(g_mtx); std::vector<std::pair<std::wstring,size_t>> out; for(auto &e: g_entries){ for(auto &iv: e.intervals){ for(size_t i=iv.a;i<=iv.b && i-iv.a<1024;++i) out.push_back({e.mod,i}); } } return out; }
}
}
