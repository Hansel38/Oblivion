#include "../pch.h"
#include "../include/DigitalSignatureScanner.h"
#include "../include/DigitalSignature.h"
#include "../include/Logger.h"
#include "../include/Utils.h"
#include "../include/EventReporter.h"
#include "../include/PublisherWhitelist.h"
#include <windows.h>
#include <vector>
#include <string>
#include <mutex>
#include <thread>
#include <chrono>

namespace OblivionEye {

    static std::mutex g_paths_mtx;
    static std::vector<std::wstring> g_paths;

    DigitalSignatureScanner& DigitalSignatureScanner::Instance() { static DigitalSignatureScanner s; return s; }

    void DigitalSignatureScanner::AddCriticalPath(const std::wstring& path) {
        std::lock_guard<std::mutex> lk(g_paths_mtx);
        g_paths.push_back(path);
    }

    void DigitalSignatureScanner::Start(unsigned intervalMs) {
        if (m_running.exchange(true)) return;
        std::thread([this, intervalMs]() { Loop(intervalMs); }).detach();
    }

    void DigitalSignatureScanner::Stop() { m_running = false; }

    bool DigitalSignatureScanner::ScanPaths() {
        std::vector<std::wstring> snapshot;
        {
            std::lock_guard<std::mutex> lk(g_paths_mtx);
            snapshot = g_paths;
        }
        const auto& trusted = PublisherWhitelist::GetTrusted();
        for (const auto& p : snapshot) {
            bool violation = false;
            if (!trusted.empty()) {
                // Mode whitelist: harus signed oleh publisher terpercaya
                if (!PublisherWhitelist::IsFileSignedByTrusted(p)) violation = true;
            } else {
                // Mode basic: cukup signed
                if (!VerifyFileIsSigned(p)) violation = true;
            }
            if (violation) {
                EventReporter::SendDetection(L"DigitalSignature", p);
                ShowDetectionAndExit(L"File tidak memenuhi kebijakan signature: " + p);
                return true;
            }
        }
        return false;
    }

    void DigitalSignatureScanner::Loop(unsigned intervalMs) {
        Log(L"DigitalSignatureScanner start");
        while (m_running) {
            if (ScanPaths()) return; 
            std::this_thread::sleep_for(std::chrono::milliseconds(intervalMs));
        }
        Log(L"DigitalSignatureScanner stop");
    }
}
