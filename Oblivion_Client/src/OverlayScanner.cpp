#include "../pch.h"
#include "../include/OverlayScanner.h"
#include "../include/DetectionCorrelator.h"
#include "../include/Config.h"
#include "../include/OverlayBlacklist.h"
#include "../include/Utils.h"
#include "../include/Logger.h"
#include "../include/EventReporter.h"
#include "../include/PublisherWhitelist.h"
#include <windows.h>
#include <string>
#include <algorithm>
#include <vector>

// Heuristik CE terintegrasi di OverlayScanner (tanpa detector baru)
// Skema skor:
// +2 class root mengandung TMainForm / TApplication
// +2 title mengandung "cheat engine"
// +1 >=2 listview child
// +1 >=8 edit child
// +1 child text mengandung pointer / scan
// +1 menu memiliki >=3 kata kunci (file/edit/table/memory/scan)
// Trigger jika skor >=4
// Cooldown global 5 menit; HWND yang sudah dilaporkan disimpan (runtime) agar tidak spam.

namespace OblivionEye {

    namespace {
    // State heuristik CE hanya diakses dari thread scheduler tunggal (non-concurrent).
    // Jika di masa depan Tick dijalankan multi-thread, lindungi struktur ini dengan mutex.
    static unsigned long long g_lastCEReportTick = 0;
        static std::vector<HWND> g_reportedCE; // sederhana; jumlah kecil
    using namespace OblivionEye::Config; // gunakan CE_* dari Config.h
        inline bool AlreadyReportedCE(HWND h) {
            return std::find(g_reportedCE.begin(), g_reportedCE.end(), h) != g_reportedCE.end();
        }
        inline void MarkReportedCE(HWND h) {
            if (!AlreadyReportedCE(h)) g_reportedCE.push_back(h);
        }
        inline unsigned long long NowMs() { return GetTickCount64(); }
        inline std::wstring ToLowerCopy(const std::wstring &s){ std::wstring r=s; std::transform(r.begin(), r.end(), r.begin(), ::towlower); return r; }
    }

    static bool IsOwnerProcessTrusted(HWND hwnd) {
        DWORD pid = 0;
        GetWindowThreadProcessId(hwnd, &pid);
        if (!pid) return false;
        HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!hProc) return false;
        wchar_t path[MAX_PATH];
        DWORD size = MAX_PATH;
        bool trusted = false;
        if (QueryFullProcessImageNameW(hProc, 0, path, &size)) {
            // Jika publisher file ini ada di whitelist, anggap overlay ini legitimate
            if (PublisherWhitelist::IsFileSignedByTrusted(path)) {
                trusted = true;
            }
        }
        CloseHandle(hProc);
        return trusted;
    }

    OverlayScanner& OverlayScanner::Instance() { static OverlayScanner s; return s; }

    bool OverlayScanner::IsBlacklistedWindow(HWND hwnd) {
    wchar_t title[OblivionEye::Config::WINDOW_TITLE_MAX] = {};
        wchar_t cls[128] = {};
    GetWindowTextW(hwnd, title, OblivionEye::Config::WINDOW_TITLE_MAX);
        GetClassNameW(hwnd, cls, 128);

        std::wstring titleL = ToLower(title);
        std::wstring clsL = ToLower(cls);

        // Jika window berasal dari proses trusted publisher -> whitelist overlay tsb
        if (IsOwnerProcessTrusted(hwnd)) {
            return false; // skip semua pengecekan blacklist (overlay legit)
        }

        for (const auto& t : GetBlacklistedWindowTitles()) {
            if (!t.empty() && titleL.find(t) != std::wstring::npos) {
                EventReporter::SendDetection(L"OverlayScanner", title);
                ShowDetectionAndExit(std::wstring(L"Overlay: ") + title);
                return true;
            }
        }
        for (const auto& c : GetBlacklistedWindowClasses()) {
            if (!c.empty() && clsL.find(c) != std::wstring::npos) {
                EventReporter::SendDetection(L"OverlayScanner", cls);
                ShowDetectionAndExit(std::wstring(L"Overlay: ") + cls);
                return true;
            }
        }
        return false;
    }

    int OverlayScanner::ScorePotentialCheatEngine(HWND hwnd) {
        if (!IsWindowVisible(hwnd)) return 0;
        LONG style = GetWindowLongW(hwnd, GWL_STYLE);
        if (style & WS_CHILD) return 0;
        RECT rc{}; if (!GetWindowRect(hwnd, &rc)) return 0;
    if ((rc.right-rc.left) < CE_MIN_WIDTH || (rc.bottom-rc.top) < CE_MIN_HEIGHT) return 0;

        wchar_t cls[256]{}; GetClassNameW(hwnd, cls, 255);
        wchar_t title[512]{}; GetWindowTextW(hwnd, title, 511);
        std::wstring lcls = ToLowerCopy(cls);
        std::wstring ltitle = ToLowerCopy(title);
        int score = 0;
        if (lcls.find(L"tmainform") != std::wstring::npos || lcls.find(L"tapplication") != std::wstring::npos) score += 2;
        if (ltitle.find(L"cheat engine") != std::wstring::npos) score += 2;

        struct ChildCtx { int edits=0; int lists=0; bool pointer=false; int scanned=0; int uiHits=0; bool earlyStop=false; } ctx;
        auto enumChild = [](HWND c, LPARAM p)->BOOL {
            auto *ctx = reinterpret_cast<ChildCtx*>(p);
            if (ctx->earlyStop) return FALSE;
            if (++ctx->scanned > 700) return FALSE;
            wchar_t ccls[128]{}; GetClassNameW(c, ccls, 127);
            std::wstring lc = ToLowerCopy(ccls);
            if (lc == L"edit") ctx->edits++;
            else if (lc.find(L"listview") != std::wstring::npos || lc.find(L"tlistview") != std::wstring::npos) ctx->lists++;
            wchar_t ctitle[256]{}; if (GetWindowTextW(c, ctitle, 255) > 0) {
                std::wstring lt = ToLowerCopy(ctitle);
                if (lt.find(L"pointer") != std::wstring::npos || lt.find(L"scan") != std::wstring::npos)
                    ctx->pointer = true;
                // Keyword UI khas CE (multi-bahasa dasar bisa ditambah policy nantinya)
                static const std::wstring uiKeys[] = { L"first scan", L"next scan", L"value type", L"add address", L"pointer scan", L"memory view" };
                for (auto &k : uiKeys) if (lt.find(k) != std::wstring::npos) { ctx->uiHits++; break; }
                if (ctx->uiHits >= CE_EARLYSTOP_UI && ctx->lists >= CE_EARLYSTOP_LISTS && ctx->edits >= CE_EARLYSTOP_EDITS) ctx->earlyStop = true; // cukup bukti
            }
            return TRUE;
        };
        EnumChildWindows(hwnd, enumChild, (LPARAM)&ctx);
    if (ctx.lists >= CE_REQ_LISTS) score += 1;
    if (ctx.edits >= CE_REQ_EDITS) score += 1;
        if (ctx.pointer) score += 1;
    if (ctx.uiHits >= CE_UI_HITS_SCORE1) score += 1; // kumpulan tombol/label penting
    if (ctx.uiHits >= CE_UI_HITS_SCORE2) score += 1; // tambahan jika sangat lengkap

        HMENU menu = GetMenu(hwnd);
        if (menu) {
            int cnt = (std::min)(10, GetMenuItemCount(menu));
            int hits = 0; const std::wstring keys[] = { L"file", L"edit", L"table", L"memory", L"scan" };
            wchar_t buf[128];
            for (int i=0;i<cnt;i++) {
                if (GetMenuStringW(menu, i, buf, 127, MF_BYPOSITION)) {
                    std::wstring lb = ToLowerCopy(buf);
                    for (auto &k : keys) if (lb.find(k) != std::wstring::npos) { hits++; break; }
                }
            }
            if (hits >= 3) score += 1;
        }
        return score;
    }

    bool OverlayScanner::HeuristicDetectCheatEngine(HWND hwnd) {
        unsigned long long now = NowMs();
    if (now - g_lastCEReportTick < CE_COOLDOWN_MS) return false; // cooldown global
        if (AlreadyReportedCE(hwnd)) return false;
        int score = ScorePotentialCheatEngine(hwnd);
    if (score >= CE_SCORE_THRESHOLD) {
            g_lastCEReportTick = now;
            MarkReportedCE(hwnd);
            wchar_t title[256]{}; GetWindowTextW(hwnd, title, 255);
            std::wstring detail = L"CEHeuristic score=" + std::to_wstring(score) + L" title='" + title + L"'";
            EventReporter::SendDetection(L"OverlayScanner", detail);
            ShowDetectionAndExit(detail);
            return true;
        } else if (score >= 2) { // partial signal
            wchar_t title[128]{}; GetWindowTextW(hwnd,title,127);
            std::wstring detail = L"partial score=" + std::to_wstring(score) + L" title='" + std::wstring(title) + L"'";
            DetectionCorrelator::Instance().Report(L"CE_PARTIAL", detail, Config::CE_PARTIAL_SCORE);
        }
        return false;
    }

    BOOL CALLBACK OverlayScanner::EnumWindowsThunk(HWND hwnd, LPARAM lParam) {
        auto self = reinterpret_cast<OverlayScanner*>(lParam);
        if (!IsWindowVisible(hwnd)) return TRUE;
        // Urutan: blacklist statis dulu; jika lolos coba heuristik CE.
        if (!self->IsBlacklistedWindow(hwnd)) {
            self->HeuristicDetectCheatEngine(hwnd);
        }
        return TRUE; // stop only via ShowDetectionAndExit (process exit)
    }

    void OverlayScanner::Tick() {
        EnumWindows(OverlayScanner::EnumWindowsThunk, reinterpret_cast<LPARAM>(this));
    }
}
