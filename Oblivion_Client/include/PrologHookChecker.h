#pragma once
#include <atomic>
#include <vector>
#include <string>
#include <mutex>

namespace OblivionEye {
    struct PrologTarget {
        std::wstring module; // lowercase module name (e.g. kernel32.dll)
        std::string function; // function name (ANSI)
        size_t minBytes; // bytes to snapshot
    };

    class PrologHookChecker {
    public:
        static PrologHookChecker& Instance();
        void Start(unsigned intervalMs = 30000); // default 30s
        void Stop();
        // Tambah target API baru secara dinamis (akan diikutkan pada scan berikut)
        void AddTarget(const std::wstring& moduleName, const std::string& funcName, size_t minBytes = 8);
        // Paksa re-capture baseline semua target (misal setelah update modul)
        void Rebaseline();
        // Enumerasi target (read-only snapshot)
        std::vector<PrologTarget> GetTargets();
    private:
        PrologHookChecker() = default;
        void Loop(unsigned intervalMs);
        bool Scan();
        bool CheckFunction(size_t index);
        void CaptureBaselines(bool forceAll = false);
        bool m_baselineCaptured = false;
        std::atomic<bool> m_running{ false };
        std::vector<PrologTarget> m_targets; // static + dynamic
        std::vector<std::vector<unsigned char>> m_baselines;
        std::mutex m_mtx; // protect targets & baselines
    };
}
