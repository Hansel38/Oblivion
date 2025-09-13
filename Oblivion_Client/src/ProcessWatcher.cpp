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
#include <wbemidl.h>
#include <comdef.h>
#pragma comment(lib, "wbemuuid.lib")

namespace OblivionEye {

    static bool IsBlacklistedName(const std::wstring& nameLower) {
        for (const auto& item : GetBlacklistedProcessNames()) {
            if (nameLower == ToLower(item)) return true;
        }
        return false;
    }

    ProcessWatcher& ProcessWatcher::Instance() {
        static ProcessWatcher inst;
        return inst;
    }

    void ProcessWatcher::Start() {
        if (m_running.exchange(true)) return;
        std::thread([this]() {
            Log(L"ProcessWatcher mulai: initial scan");
            InitialScan();
            Log(L"ProcessWatcher: monitoring proses baru (WMI jika tersedia)");
            WatchNewProcesses();
        }).detach();
    }

    void ProcessWatcher::Stop() {
        m_running = false;
    }

    void ProcessWatcher::InitialScan() {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) return;
        PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
        if (Process32FirstW(snap, &pe)) {
            do {
                std::wstring nameLower = ToLower(pe.szExeFile);
                if (IsBlacklistedName(nameLower)) {
                    EventReporter::SendDetection(L"ProcessWatcher", pe.szExeFile);
                    ShowDetectionAndExit(pe.szExeFile);
                    CloseHandle(snap);
                    return;
                }
            } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);
    }

    // WMI event watcher: __InstanceCreationEvent for Win32_Process
    static bool WatchWithWmi(std::atomic<bool>& running) {
        HRESULT hr = CoInitializeEx(0, COINIT_MULTITHREADED);
        bool comInit = SUCCEEDED(hr);
        if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) return false;

        hr = CoInitializeSecurity(NULL, -1, NULL, NULL,
            RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
        // If already initialized, continue.

        IWbemLocator* pLoc = nullptr;
        hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
        if (FAILED(hr) || !pLoc) { if (comInit) CoUninitialize(); return false; }

        IWbemServices* pSvc = nullptr;
        hr = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, 0, 0, 0, &pSvc);
        if (FAILED(hr) || !pSvc) { pLoc->Release(); if (comInit) CoUninitialize(); return false; }

        hr = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
            RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
        if (FAILED(hr)) { pSvc->Release(); pLoc->Release(); if (comInit) CoUninitialize(); return false; }

        IEnumWbemClassObject* pEnumerator = nullptr;
        BSTR query = SysAllocString(L"SELECT TargetInstance FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'");
        BSTR lang = SysAllocString(L"WQL");
        hr = pSvc->ExecNotificationQuery(lang, query, WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
        SysFreeString(query); SysFreeString(lang);
        if (FAILED(hr) || !pEnumerator) {
            pSvc->Release(); pLoc->Release(); if (comInit) CoUninitialize(); return false;
        }

        while (running) {
            IWbemClassObject* pObj = nullptr; ULONG ret = 0;
            hr = pEnumerator->Next(1000, 1, &pObj, &ret); // 1s timeout to check running flag
            if (hr == WBEM_S_TIMEDOUT) continue;
            if (FAILED(hr) || ret == 0) break;

            VARIANT vtInst; VariantInit(&vtInst);
            if (SUCCEEDED(pObj->Get(L"TargetInstance", 0, &vtInst, 0, 0)) && vtInst.vt == VT_UNKNOWN && vtInst.punkVal) {
                IWbemClassObject* pTarget = nullptr;
                if (SUCCEEDED(vtInst.punkVal->QueryInterface(IID_IWbemClassObject, (void**)&pTarget)) && pTarget) {
                    VARIANT vtName; VariantInit(&vtName);
                    if (SUCCEEDED(pTarget->Get(L"Name", 0, &vtName, 0, 0)) && vtName.vt == VT_BSTR && vtName.bstrVal) {
                        std::wstring nameLower = ToLower(vtName.bstrVal);
                        if (IsBlacklistedName(nameLower)) {
                            EventReporter::SendDetection(L"ProcessWatcher.WMI", vtName.bstrVal);
                            VariantClear(&vtName);
                            pTarget->Release();
                            VariantClear(&vtInst);
                            pObj->Release();
                            pEnumerator->Release();
                            pSvc->Release();
                            pLoc->Release();
                            if (comInit) CoUninitialize();
                            ShowDetectionAndExit(vtName.bstrVal);
                            return true; // unreachable after ExitProcess, but keep for structure
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
        return true; // gracefully ended (stop requested)
    }

    void ProcessWatcher::WatchNewProcesses() {
        // Coba gunakan WMI event; jika gagal, fallback ke polling ringan
        if (!WatchWithWmi(m_running)) {
            Log(L"ProcessWatcher: WMI gagal, fallback ke polling");
            std::vector<DWORD> known;
            known.reserve(1024);
            while (m_running) {
                HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
                if (snap == INVALID_HANDLE_VALUE) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(500));
                    continue;
                }
                std::vector<DWORD> current;
                current.reserve(1024);

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
                DWORD prevSize = (DWORD)known.size();
                known.swap(current);
                DWORD sleepMs = (prevSize == known.size()) ? 1200 : 750;
                std::this_thread::sleep_for(std::chrono::milliseconds(sleepMs));
            }
        }
    }

    void ProcessWatcher::Tick() {
        // Health check: if previously running but thread died unexpectedly (rare), restart.
        if (!m_running.load()) {
            Start();
        }
    }
}
