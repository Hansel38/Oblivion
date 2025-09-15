#include "../pch.h"
#include "../include/DetectionCorrelator.h"
#include "../include/EventReporter.h"
#include "../include/Logger.h"
#include "../include/PipeClient.h"
#include <windows.h>
#include <sstream>

namespace OblivionEye {
namespace {
    inline unsigned long long NowMs() { return GetTickCount64(); }

    static std::string Narrow(const std::wstring &w) {
        std::string s; s.reserve(w.size());
        for (wchar_t c : w) s.push_back((c >= 32 && c < 127) ? static_cast<char>(c) : '?');
        return s;
    }
}

DetectionCorrelator &DetectionCorrelator::Instance() {
    static DetectionCorrelator s; return s;
}

void DetectionCorrelator::Prune(unsigned long long now) {
    const unsigned windowMs = 60000;        // correlation window
    const unsigned pruneIntervalMs = 5000;  // prune every 5s max
    if (now - m_lastPruneTick < pruneIntervalMs) return;
    m_lastPruneTick = now;

    size_t writeIdx = 0;
    for (size_t i = 0; i < m_entries.size(); ++i) {
        if (now - m_entries[i].tick <= windowMs) {
            if (writeIdx != i) m_entries[writeIdx] = m_entries[i];
            ++writeIdx;
        }
    }
    if (writeIdx < m_entries.size()) m_entries.resize(writeIdx);
}

static unsigned ComputeScoreAndCounts(
    unsigned long long now,
    const std::vector<DetectionCorrelator::Entry> &entries,
    unsigned &eat, unsigned &iat, unsigned &prolog, unsigned &syscall) {
    eat = iat = prolog = syscall = 0;
    for (const auto &e : entries) {
        if (now - e.tick > 60000) continue;
        if (e.cat == L"EAT") ++eat; else if (e.cat == L"IAT") ++iat; else if (e.cat == L"PROLOG") ++prolog; else if (e.cat == L"SYSCALL") ++syscall;
    }
    return eat*1 + iat*2 + prolog*3 + syscall*4; // weighted score
}

void DetectionCorrelator::Report(const std::wstring &category, const std::wstring &detail) {
    const unsigned scoreThreshold = 5;
    unsigned long long now = NowMs();
    std::lock_guard<std::mutex> lk(m_mtx);

    Prune(now);
    m_entries.push_back(Entry{ category, detail, now });

    unsigned eat=0, iat=0, prolog=0, syscall=0;
    unsigned score = ComputeScoreAndCounts(now, m_entries, eat, iat, prolog, syscall);
    if (score < scoreThreshold) return;

    std::wstringstream keyStream; keyStream << eat << L"-" << iat << L"-" << prolog << L"-" << syscall;
    auto comboKey = keyStream.str();
    if (!m_sentCombos.insert(comboKey).second) return; // already reported

    std::wstringstream msg; msg << L"HookCorrelation score=" << score
        << L" (EAT=" << eat << L" IAT=" << iat << L" PROLOG=" << prolog << L" SYSCALL=" << syscall << L")";

    EventReporter::SendDetection(L"HookCorrelation", msg.str());
    Log(msg.str());
    if (PipeClient::Instance().IsRunning()) {
        PipeClient::Instance().Send("INFO|CORR|HOOK|" + Narrow(msg.str()));
    }
}
}
