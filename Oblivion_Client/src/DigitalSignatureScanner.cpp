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
namespace {
    std::mutex g_pathsMtx;
    std::vector<std::wstring> g_paths; // critical paths to validate

    bool IsTrustedPublisherMatch(const std::wstring &publisherLower) {
        const auto &trusted = PublisherWhitelist::GetTrusted();
        for (const auto &t : trusted) {
            if (publisherLower == t)
                return true;
        }
        return false;
    }

    bool ValidatePathAgainstPolicy(const std::wstring &path) {
        const auto &trusted = PublisherWhitelist::GetTrusted();

        if (!trusted.empty()) {
            // Whitelist mode: file must be signed and CN in whitelist
            auto info = VerifyFileSignatureExtended(path, false); // offline revocation for perf
            if (!info.trusted)
                return false; // chain invalid
            auto publisherLower = info.publisherCN;
            for (auto &ch : publisherLower) ch = static_cast<wchar_t>(towlower(ch));
            return IsTrustedPublisherMatch(publisherLower);
        }
        // Basic mode: just require it to be signed
        return VerifyFileIsSigned(path);
    }
}

DigitalSignatureScanner &DigitalSignatureScanner::Instance() { static DigitalSignatureScanner s; return s; }

void DigitalSignatureScanner::AddCriticalPath(const std::wstring &path) {
    std::lock_guard<std::mutex> lk(g_pathsMtx);
    g_paths.push_back(path);
}

bool DigitalSignatureScanner::ScanPaths() {
    std::vector<std::wstring> snapshot;
    {
        std::lock_guard<std::mutex> lk(g_pathsMtx);
        snapshot = g_paths;
    }

    for (const auto &p : snapshot) {
        if (ValidatePathAgainstPolicy(p))
            continue;
        EventReporter::SendDetection(L"DigitalSignature", p);
        ShowDetectionAndExit(L"File tidak memenuhi kebijakan signature: " + p);
        return true;
    }
    return false;
}

void DigitalSignatureScanner::Tick() { ScanPaths(); }
}
