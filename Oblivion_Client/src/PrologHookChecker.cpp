#include "../pch.h"
#include "../include/PrologHookChecker.h"
#include "../include/Logger.h"
#include "../include/EventReporter.h"
#include "../include/Utils.h"
#include <windows.h>
#include <psapi.h>
#include <vector>
#include <string>
#include <algorithm>
#include <mutex>

#pragma comment(lib, "psapi.lib")

namespace OblivionEye {

    static unsigned char* ResolveFuncPtr(const std::wstring& moduleName, const std::string& funcName) {
        HMODULE hMod = GetModuleHandleW(moduleName.c_str()); if (!hMod) return nullptr; FARPROC fp = GetProcAddress(hMod, funcName.c_str()); if (!fp) return nullptr; return (unsigned char*)fp;
    }

    PrologHookChecker& PrologHookChecker::Instance() { static PrologHookChecker s; return s; }

    std::vector<PrologTarget> PrologHookChecker::GetTargets() { std::lock_guard<std::mutex> lk(m_mtx); return m_targets; }

    void PrologHookChecker::AddTarget(const std::wstring& moduleName, const std::string& funcName, size_t minBytes) {
        std::lock_guard<std::mutex> lk(m_mtx); PrologTarget t{ ToLower(moduleName), funcName, minBytes }; m_targets.push_back(t); m_baselines.emplace_back(); }

    void PrologHookChecker::Rebaseline() { CaptureBaselines(true); }

    void PrologHookChecker::CaptureBaselines(bool forceAll) {
        std::lock_guard<std::mutex> lk(m_mtx);
        if (!m_baselineCaptured || forceAll) {
            if (!m_baselineCaptured) {
                m_targets = {
                    { L"kernel32.dll", "VirtualProtect", 8 },
                    { L"kernel32.dll", "CreateRemoteThread", 8 },
                    { L"kernel32.dll", "WriteProcessMemory", 8 },
                    { L"kernel32.dll", "ReadProcessMemory", 8 },
                    { L"kernel32.dll", "OpenProcess", 8 },
                    { L"ntdll.dll",    "NtOpenProcess", 8 },
                    { L"ntdll.dll",    "NtWriteVirtualMemory", 8 },
                    { L"ntdll.dll",    "NtReadVirtualMemory", 8 },
                };
                m_baselines.clear();
            }
            if (m_baselines.size() < m_targets.size()) m_baselines.resize(m_targets.size());
            for (size_t i = 0; i < m_targets.size(); ++i) {
                auto& tgt = m_targets[i]; unsigned char* p = ResolveFuncPtr(tgt.module, tgt.function); if (p) { m_baselines[i].assign(p, p + tgt.minBytes); } else if (forceAll) { m_baselines[i].clear(); }
            }
            m_baselineCaptured = true;
            Log(L"PrologHookChecker baseline captured (targets=" + std::to_wstring(m_targets.size()) + L")");
        }
    }

    bool PrologHookChecker::CheckFunction(size_t index) {
        std::lock_guard<std::mutex> lk(m_mtx);
        if (index >= m_targets.size()) return true;
        auto& tgt = m_targets[index]; unsigned char* p = ResolveFuncPtr(tgt.module, tgt.function); if (!p) return true;
        if (p[0] == 0xE9 || p[0] == 0xE8 || p[0] == 0xC2 || p[0] == 0xC3 || p[0] == 0xCB || p[0] == 0xCA) return false;
        if (p[0] == 0xFF && (p[1] == 0x25 || p[1] == 0x15)) return false;
        if (p[0] == 0x68 && p[5] == 0xC3) return false;
        if (index < m_baselines.size() && !m_baselines[index].empty()) {
            auto& base = m_baselines[index]; for (size_t i = 0; i < base.size(); ++i) { if (p[i] != base[i]) return false; }
        }
        return true;
    }

    bool PrologHookChecker::Scan() {
        for (size_t i = 0; i < m_targets.size(); ++i) {
            if (!CheckFunction(i)) {
                auto& t = m_targets[i]; std::wstring msg = L"Inline hook terdeteksi: "; msg += t.module + L"!" + std::wstring(t.function.begin(), t.function.end());
                EventReporter::SendDetection(L"PrologHookChecker", msg); ShowDetectionAndExit(msg); return true;
            }
        }
        return false;
    }

    void PrologHookChecker::Tick() {
        if (!m_baselineCaptured) CaptureBaselines(false); else Scan();
    }
}
