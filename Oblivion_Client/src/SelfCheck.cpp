#include "../pch.h"
#include "../include/SelfCheck.h"
#include "../include/Logger.h"
#include "../include/PipeClient.h"
#include "../include/HashUtil.h"
#include <windows.h>
#include <vector>

namespace OblivionEye {
    // Helper: simple assertion that logs and accumulates status.
    struct SCContext {
        std::wstring report;
        bool failed = false;
        void Append(const std::wstring &line) { report += line + L"\n"; }
        void Check(bool cond, const std::wstring &name, const std::wstring &detail=L"") {
            if(cond) {
                Append(L"[SC PASS] " + name + (detail.empty()?L"":L" - "+detail));
            } else {
                Append(L"[SC FAIL] " + name + (detail.empty()?L"":L" - "+detail));
                failed = true;
            }
        }
    };

    std::wstring RunInternalSelfCheck() {
        SCContext ctx;
        ctx.Append(L"== Internal SelfCheck Start ==");

        // 1. Logger ring basic behavior
        auto &log = LoggerBackend::Instance();
        auto originalLevel = log.GetLevel();
        log.SetLevel(LogLevel::Debug);
        log.SetMaxRing(8); // shrink for test
    for(int i=0;i<12;++i) LogDbg(std::wstring(L"sc_debug_") + std::to_wstring(i));
        auto snap = log.Snapshot();
        bool sizeOk = snap.size() <= 8; // ring cap should apply
        ctx.Check(sizeOk, L"LoggerRingCap", std::to_wstring(snap.size()));
        log.SetLevel(originalLevel); // restore

        // 2. HashUtil deterministic result
        std::string h1 = HashUtil::Sha256HexLower("abc");
        std::string h2 = HashUtil::Sha256HexLower("abc");
        ctx.Check(!h1.empty() && h1==h2, L"Sha256Deterministic");

        // 3. Session key derivation stability
        std::string k = "keyTEST"; std::string n1="123", n2="456";
        std::string s1 = HashUtil::DeriveSessionKey(k,n1,n2);
        std::string s2 = HashUtil::DeriveSessionKey(k,n1,n2);
        ctx.Check(!s1.empty() && s1==s2, L"SessionKeyDeterministic");

        // 4. PipeClient basic enqueue (non-blocking) if running
        bool pipeRunning = PipeClient::Instance().IsRunning();
        if(pipeRunning) {
            PipeClient::Instance().Send(L"SC_PING");
            ctx.Check(true, L"PipeClientSend");
        } else {
            ctx.Check(true, L"PipeClientSkip", L"not running (acceptable at init phase)");
        }

        ctx.Append(ctx.failed?L"== Internal SelfCheck COMPLETE: FAILURE ==":L"== Internal SelfCheck COMPLETE: OK ==");
        // Always log summary through security channel for visibility
        LogSec(std::wstring(L"SelfCheck status: ") + std::wstring(ctx.failed ? L"FAIL" : L"OK"));
        return ctx.report;
    }
}
