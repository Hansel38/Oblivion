#include "../pch.h"
#include "../include/IntegrityChunkWhitelist.h"
#include <algorithm>
#include <vector>

namespace OblivionEye {
namespace IntegrityChunkWhitelist {
    struct Entry { std::wstring mod; size_t idx; };
    static std::vector<Entry> g_entries; // requires <vector>
    static std::mutex g_mtx;

    static std::wstring ToLower(const std::wstring& s){ std::wstring r=s; std::transform(r.begin(), r.end(), r.begin(), ::towlower); return r; }

    void Add(const std::wstring& moduleNameLower, size_t chunkIndex){
        std::lock_guard<std::mutex> lk(g_mtx);
        auto low = ToLower(moduleNameLower);
        for (auto& e : g_entries) if (e.mod == low && e.idx == chunkIndex) return;
        g_entries.push_back({low, chunkIndex});
    }

    bool IsWhitelisted(const std::wstring& moduleNameLower, size_t chunkIndex){
        std::lock_guard<std::mutex> lk(g_mtx);
        auto low = ToLower(moduleNameLower);
        for (auto& e : g_entries) if (e.mod == low && e.idx == chunkIndex) return true;
        return false;
    }

    void Clear(){ std::lock_guard<std::mutex> lk(g_mtx); g_entries.clear(); }

    std::vector<std::pair<std::wstring,size_t>> GetAll(){
        std::lock_guard<std::mutex> lk(g_mtx);
        std::vector<std::pair<std::wstring,size_t>> out; out.reserve(g_entries.size());
        for (auto& e : g_entries) out.push_back({e.mod, e.idx});
        return out;
    }
}
}
