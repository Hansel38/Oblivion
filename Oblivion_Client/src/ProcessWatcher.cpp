#include "../pch.h"
#include "../include/ProcessWatcher.h"
#include "../include/Blacklist.h"
#include "../include/Utils.h"
#include "../include/Logger.h"
#include "../include/EventReporter.h"

#include <windows.h>
#include <tlhelp32.h>
#include <thread>
#include <vector>
#include <string>
#include <algorithm>
#include "../include/Config.h"
#include <wbemidl.h>
#include <comdef.h>

#pragma comment(lib, "wbemuuid.lib")

namespace OblivionEye {
namespace {
    bool IsBlacklistedName(const std::wstring &nameLower) {
        for (const auto &item : GetBlacklistedProcessNames()) {
            if (nameLower == ToLower(item))
                return true;
        }
        return false;
    }

    bool WatchWithWmi(std::atomic<bool> &running) {
        HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        bool comInit = SUCCEEDED(hr);
        if (FAILED(hr) && hr != RPC_E_CHANGED_MODE)
            return false;

        // Initialize security (ignore failure if already initialized)
        CoInitializeSecurity(nullptr, -1, nullptr, nullptr,
                             RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
                             nullptr, EOAC_NONE, nullptr);

        IWbemLocator *pLoc = nullptr;
        hr = CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
                              IID_IWbemLocator, reinterpret_cast<LPVOID*>(&pLoc));
        if (FAILED(hr) || !pLoc) { if (comInit) CoUninitialize(); return false; }

        IWbemServices *pSvc = nullptr;
        hr = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), nullptr, nullptr, 0, 0, 0, 0, &pSvc);
        if (FAILED(hr) || !pSvc) { pLoc->Release(); if (comInit) CoUninitialize(); return false; }

        hr = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
                               RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
                               nullptr, EOAC_NONE);
        if (FAILED(hr)) { pSvc->Release(); pLoc->Release(); if (comInit) CoUninitialize(); return false; }

        IEnumWbemClassObject *pEnumerator = nullptr;
        BSTR query = SysAllocString(L"SELECT TargetInstance FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'");
        BSTR lang  = SysAllocString(L"WQL");
        hr = pSvc->ExecNotificationQuery(lang, query, WBEM_FLAG_RETURN_IMMEDIATELY, nullptr, &pEnumerator);
        SysFreeString(query); SysFreeString(lang);
        if (FAILED(hr) || !pEnumerator) {
            pSvc->Release(); pLoc->Release(); if (comInit) CoUninitialize(); return false; }

        while (running) {
            IWbemClassObject *pObj = nullptr; ULONG ret = 0;
            hr = pEnumerator->Next(1000, 1, &pObj, &ret); // 1s poll to check flag
            if (hr == WBEM_S_TIMEDOUT) continue;
            if (FAILED(hr) || ret == 0) break;

            VARIANT vtInst; VariantInit(&vtInst);
            if (SUCCEEDED(pObj->Get(L"TargetInstance", 0, &vtInst, nullptr, nullptr)) && vtInst.vt == VT_UNKNOWN && vtInst.punkVal) {
                IWbemClassObject *pTarget = nullptr;
                if (SUCCEEDED(vtInst.punkVal->QueryInterface(IID_IWbemClassObject, reinterpret_cast<void**>(&pTarget))) && pTarget) {
                    VARIANT vtName; VariantInit(&vtName);
                    if (SUCCEEDED(pTarget->Get(L"Name", 0, &vtName, nullptr, nullptr)) && vtName.vt == VT_BSTR && vtName.bstrVal) {
                        std::wstring nameLower = ToLower(vtName.bstrVal);
                        if (IsBlacklistedName(nameLower)) {
                            EventReporter::SendDetection(L"ProcessWatcher.WMI", vtName.bstrVal);
                            VariantClear(&vtName); pTarget->Release(); VariantClear(&vtInst); pObj->Release();
                            pEnumerator->Release(); pSvc->Release(); pLoc->Release(); if (comInit) CoUninitialize();
                            ShowDetectionAndExit(vtName.bstrVal); return true; // ExitProcess expected
                        }
                    }
                    VariantClear(&vtName);
                    pTarget->Release();
                }
                VariantClear(&vtInst);
            }
            pObj->Release();
        }

        pEnumerator->Release();
        pSvc->Release();
        pLoc->Release();
        if (comInit) CoUninitialize();
        return true; // graceful end
    }
}

ProcessWatcher &ProcessWatcher::Instance() { static ProcessWatcher inst; return inst; }

void ProcessWatcher::Start() {
    if (m_running.exchange(true)) return;
    std::thread([this]() {
        Log(L"ProcessWatcher: initial scan");
        InitialScan();
        Log(L"ProcessWatcher: monitoring (WMI if available)");
        WatchNewProcesses();
    }).detach();
}

void ProcessWatcher::Stop() { m_running = false; }

void ProcessWatcher::InitialScan() {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            std::wstring nameLower = ToLower(pe.szExeFile);
            if (IsBlacklistedName(nameLower)) {
                EventReporter::SendDetection(L"ProcessWatcher", pe.szExeFile);
                CloseHandle(snap);
                ShowDetectionAndExit(pe.szExeFile);
                return;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
}

void ProcessWatcher::WatchNewProcesses() {
    // Prefer WMI events; fall back to polling if unavailable
    if (!WatchWithWmi(m_running)) {
        Log(L"ProcessWatcher: WMI unavailable, fallback to polling");
    std::vector<DWORD> known; known.reserve(OblivionEye::Config::PROCESS_ENUM_RESERVE);
        while (m_running) {
            HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (snap == INVALID_HANDLE_VALUE) {
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
                continue;
            }
            std::vector<DWORD> current; current.reserve(OblivionEye::Config::PROCESS_ENUM_RESERVE);
            PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
            if (Process32FirstW(snap, &pe)) {
                do {
                    current.push_back(pe.th32ProcessID);
                    if (std::find(known.begin(), known.end(), pe.th32ProcessID) == known.end()) {
                        std::wstring nameLower = ToLower(pe.szExeFile);
                        if (IsBlacklistedName(nameLower)) {
                            CloseHandle(snap);
                            EventReporter::SendDetection(L"ProcessWatcher", pe.szExeFile);
                            ShowDetectionAndExit(pe.szExeFile);
                            return;
                        }
                    }
                } while (Process32NextW(snap, &pe));
            }
            CloseHandle(snap);
            DWORD prevSize = static_cast<DWORD>(known.size());
            known.swap(current);
            DWORD sleepMs = (prevSize == known.size()) ? Config::PROC_WATCH_POLL_IDLE_MS : Config::PROC_WATCH_POLL_ACTIVE_MS;
            std::this_thread::sleep_for(std::chrono::milliseconds(sleepMs));
        }
    }
}

void ProcessWatcher::Tick() {
    // Health check: restart if previously started but flag cleared unexpectedly
    if (!m_running.load())
        Start();
}
}
