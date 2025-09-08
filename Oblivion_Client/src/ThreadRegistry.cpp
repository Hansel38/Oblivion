#include "../pch.h"
#include "../include/ThreadRegistry.h"
#include <mutex>
#include <algorithm>

namespace OblivionEye {
    static std::mutex g_mtx;
    static std::vector<DWORD> g_tids;

    void RegisterThreadId(DWORD tid) {
        std::lock_guard<std::mutex> lock(g_mtx);
        if (std::find(g_tids.begin(), g_tids.end(), tid) == g_tids.end())
            g_tids.push_back(tid);
    }

    void UnregisterThreadId(DWORD tid) {
        std::lock_guard<std::mutex> lock(g_mtx);
        g_tids.erase(std::remove(g_tids.begin(), g_tids.end(), tid), g_tids.end());
    }

    std::vector<DWORD> GetRegisteredThreadIds() {
        std::lock_guard<std::mutex> lock(g_mtx);
        return g_tids; // copy by value
    }
}
