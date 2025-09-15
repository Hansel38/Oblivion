#include "../pch.h"
#include "../include/PrologHookChecker.h"
#include "../include/Logger.h"
#include "../include/EventReporter.h"
#include "../include/Utils.h"
#include "../include/DetectionCorrelator.h"
#include <windows.h>
#include <psapi.h>
#include <vector>
#include <string>
#include <algorithm>
#include <mutex>

#pragma comment(lib, "psapi.lib")

namespace OblivionEye {
namespace {
    unsigned char *ResolveFuncPtr(const std::wstring &moduleName, const std::string &funcName) {
        HMODULE hMod = GetModuleHandleW(moduleName.c_str());
        if (!hMod) return nullptr;
        FARPROC fp = GetProcAddress(hMod, funcName.c_str());
        return fp ? reinterpret_cast<unsigned char*>(fp) : nullptr;
    }

    bool StartsWithRetOrJmp(const unsigned char *p) {
        // Typical immediate prolog redirection or patch patterns
        if (!p) return false;
        switch (p[0]) {
        case 0xE9: // jmp rel32
        case 0xE8: // call rel32
        case 0xC2: // ret n
        case 0xC3: // ret
        case 0xCB: // retf
        case 0xCA: // retf n
            return true;
        default:
            break;
        }
        // FF 25 / FF 15 => JMP/CALL [abs]
        if (p[0] == 0xFF && (p[1] == 0x25 || p[1] == 0x15))
            return true;
        // push imm; ret (common shell hook) => 68 xx xx xx xx C3
        if (p[0] == 0x68 && p[5] == 0xC3)
            return true;
        return false;
    }

    bool BytesDiffer(const unsigned char *cur, const std::vector<unsigned char> &baseline) {
        if (baseline.empty())
            return false; // nothing to compare
        for (size_t i = 0; i < baseline.size(); ++i)
            if (cur[i] != baseline[i])
                return true;
        return false;
    }
}

PrologHookChecker &PrologHookChecker::Instance() { static PrologHookChecker s; return s; }

std::vector<PrologTarget> PrologHookChecker::GetTargets() {
    std::lock_guard<std::mutex> lk(m_mtx);
    return m_targets;
}

void PrologHookChecker::AddTarget(const std::wstring &moduleName, const std::string &funcName, size_t minBytes) {
    std::lock_guard<std::mutex> lk(m_mtx);
    m_targets.push_back({ ToLower(moduleName), funcName, minBytes });
    m_baselines.emplace_back();
}

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
        if (m_baselines.size() < m_targets.size())
            m_baselines.resize(m_targets.size());

        for (size_t i = 0; i < m_targets.size(); ++i) {
            auto &tgt = m_targets[i];
            unsigned char *p = ResolveFuncPtr(tgt.module, tgt.function);
            if (p) {
                m_baselines[i].assign(p, p + tgt.minBytes);
            } else if (forceAll) {
                m_baselines[i].clear();
            }
        }
        m_baselineCaptured = true;
        Log(L"PrologHookChecker baseline captured (targets=" + std::to_wstring(m_targets.size()) + L")");
    }
}

bool PrologHookChecker::CheckFunction(size_t index) {
    std::lock_guard<std::mutex> lk(m_mtx);
    if (index >= m_targets.size())
        return true;

    auto &tgt = m_targets[index];
    unsigned char *p = ResolveFuncPtr(tgt.module, tgt.function);
    if (!p)
        return true; // treat missing as benign (module not present yet)

    if (StartsWithRetOrJmp(p))
        return false;

    if (index < m_baselines.size() && BytesDiffer(p, m_baselines[index]))
        return false;

    return true;
}

bool PrologHookChecker::Scan() {
    for (size_t i = 0; i < m_targets.size(); ++i) {
        if (!CheckFunction(i)) {
            auto &t = m_targets[i];
            std::wstring msg = L"Inline hook terdeteksi: " + t.module + L"!" + std::wstring(t.function.begin(), t.function.end());
            DetectionCorrelator::Instance().Report(L"PROLOG", msg);
            EventReporter::SendDetection(L"PrologHookChecker", msg);
            ShowDetectionAndExit(msg);
            return true;
        }
    }
    return false;
}

void PrologHookChecker::Tick() { if (!m_baselineCaptured) CaptureBaselines(false); else Scan(); }
}
