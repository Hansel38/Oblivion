#include "../pch.h"
#include "../include/DigitalSignatureScanner.h"
#include "../include/DigitalSignature.h"
#include "../include/Logger.h"
#include "../include/Utils.h"
#include "../include/EventReporter.h"
#include "../include/PublisherWhitelist.h"
#include "../include/SignatureTrust.h"
#include <windows.h>
#include <vector>
#include <string>
#include <mutex>

namespace OblivionEye {

    static std::mutex g_paths_mtx;
    static std::vector<std::wstring> g_paths;

    DigitalSignatureScanner& DigitalSignatureScanner::Instance() { static DigitalSignatureScanner s; return s; }

    void DigitalSignatureScanner::AddCriticalPath(const std::wstring& path) {
        std::lock_guard<std::mutex> lk(g_paths_mtx);
        g_paths.push_back(path);
    }

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
                // Mode whitelist: file harus signed oleh publisher trusted.
                auto info = VerifyFileSignatureExtended(p, false); // offline revocation for performance
                if (!info.trusted) {
                    violation = true; // tidak valid chain
                } else {
                    // publisher harus ada di whitelist
                    std::wstring lowCN = info.publisherCN; for (auto& ch : lowCN) ch = (wchar_t)towlower(ch);
                    bool found = false;
                    for (const auto& t : trusted) { if (lowCN == t) { found = true; break; } }
                    if (!found) violation = true;
                }
            } else {
                // Mode basic: cukup signed sederhana
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

    void DigitalSignatureScanner::Tick() {
        ScanPaths();
    }
}
