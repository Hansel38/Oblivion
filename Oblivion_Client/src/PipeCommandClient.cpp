#include "../pch.h"
#include "../include/PipeCommandClient.h"
#include "../include/DetectionCorrelator.h"
#include "../include/Logger.h"
#include "../include/Blacklist.h"
#include "../include/ModuleBlacklist.h"
#include "../include/Heartbeat.h"
#include "../include/OverlayBlacklist.h"
#include "../include/DriverBlacklist.h"
#include "../include/PublisherWhitelist.h"
#include "../include/DigitalSignatureScanner.h"
#include "../include/PrologHookChecker.h"
#include "../include/PipeClient.h"
#include "../include/PolicyManager.h"
#include "../include/RuntimeStats.h"
#include "../include/IntegrityChunkWhitelist.h"
#include "../include/DetectorScheduler.h"
#include "../include/Config.h"
#include "../include/StringUtil.h"
#include <windows.h>
#include <thread>
#include <string>
#include <sstream>
#include <deque>
#include "../include/Signatures.h"

namespace OblivionEye {
    static HANDLE g_hCmdPipe = INVALID_HANDLE_VALUE;
    PipeCommandClient& PipeCommandClient::Instance() { static PipeCommandClient s; return s; }

    void PipeCommandClient::Start(const std::wstring& pipeName) { if (m_running.exchange(true)) return; m_pipeName = pipeName; std::thread([this]() { WorkerLoop(); }).detach(); }
    void PipeCommandClient::Stop() { m_running = false; ClosePipe(); }
    void PipeCommandClient::ClosePipe() { if (g_hCmdPipe != INVALID_HANDLE_VALUE) { CloseHandle(g_hCmdPipe); g_hCmdPipe = INVALID_HANDLE_VALUE; } }
    void PipeCommandClient::EnsureConnected() { if (g_hCmdPipe != INVALID_HANDLE_VALUE) return; g_hCmdPipe = CreateFileW(m_pipeName.c_str(), GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr); if (g_hCmdPipe != INVALID_HANDLE_VALUE) Log(L"PipeCommandClient connected"); }

    using OblivionEye::StringUtil::Utf8ToWide;
    using OblivionEye::StringUtil::WideToUtf8;
    static void KillProcessByPid(DWORD pid) { HANDLE h=OpenProcess(PROCESS_TERMINATE,FALSE,pid); if(!h) return; TerminateProcess(h,0); CloseHandle(h);}    
    static void QuarantineFile(const std::wstring& path) { if(path.empty()) return; std::wstring newPath=path+L".quarantine"; MoveFileExW(path.c_str(),newPath.c_str(),MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH);}    

    static void SendUtf8(const std::wstring& type, const std::wstring& w) {
        if (!PipeClient::Instance().IsRunning()) return;
        auto typeUtf8 = WideToUtf8(type);
        auto payload  = WideToUtf8(w);
        if (typeUtf8.empty() || payload.empty()) return;
        PipeClient::Instance().Send("INFO|" + typeUtf8 + "|" + payload);
    }

    void PipeCommandClient::HandleCommandLine(const std::string& line) {
    static std::deque<DWORD> recentTicks; static DWORD windowMs=Config::CMD_WINDOW_MS; DWORD now = GetTickCount();
    while(!recentTicks.empty() && now - recentTicks.front() > windowMs) recentTicks.pop_front(); if (recentTicks.size() >= Config::CMD_MAX_RECENT) { return; } recentTicks.push_back(now);

        // Cooldown tracking for risky commands
        static DWORD lastKillTick = 0; static DWORD lastQuarantineTick = 0;
        static unsigned killCooldownHits = 0; static unsigned quarantineCooldownHits = 0;
    const DWORD RISK_COOLDOWN_MS = Config::CMD_RISK_COOLDOWN_MS;
    const unsigned ABUSE_THRESHOLD = Config::CMD_ABUSE_THRESHOLD;

        auto cooldownRemain = [](DWORD lastTick, DWORD now, DWORD minMs)->DWORD {
            if (now < lastTick) return 0; DWORD delta = now - lastTick; return (delta >= minMs) ? 0 : (minMs - delta);
        };

        std::istringstream iss(line); std::string cmd; iss >> cmd;
        if (cmd == "CLOSE_CLIENT") { ExitProcess(0); }
    else if (cmd == "UPDATE_BLACKLIST") { std::string name; iss>>name; if(!name.empty()) AddBlacklistedProcessName(Utf8ToWide(name)); }
    else if (cmd == "UPDATE_MODULE_BLACKLIST") { std::string name; iss>>name; if(!name.empty()) AddBlacklistedModuleName(Utf8ToWide(name)); }
    else if (cmd == "UPDATE_OVERLAY_BLACKLIST_TITLE") { std::string rest; getline(iss,rest); if(!rest.empty()&&rest[0]==' ')rest.erase(0,1); if(!rest.empty()) AddBlacklistedWindowTitle(Utf8ToWide(rest)); }
    else if (cmd == "UPDATE_OVERLAY_BLACKLIST_CLASS") { std::string rest; getline(iss,rest); if(!rest.empty()&&rest[0]==' ')rest.erase(0,1); if(!rest.empty()) AddBlacklistedWindowClass(Utf8ToWide(rest)); }
    else if (cmd == "UPDATE_DRIVER_BLACKLIST") { std::string name; iss>>name; if(!name.empty()) AddBlacklistedDriverName(Utf8ToWide(name)); }
    else if (cmd == "WHITELIST_PUBLISHER_ADD") { std::string rest; getline(iss,rest); if(!rest.empty()&&rest[0]==' ')rest.erase(0,1); if(!rest.empty()) PublisherWhitelist::AddTrusted(Utf8ToWide(rest)); }
    else if (cmd == "WHITELIST_FILE_ADD") { std::string rest; getline(iss,rest); if(!rest.empty()&&rest[0]==' ')rest.erase(0,1); if(!rest.empty()) DigitalSignatureScanner::Instance().AddCriticalPath(Utf8ToWide(rest)); }
        else if (cmd == "KILL_PROCESS") {
            DWORD pid=0; iss>>pid; if(!pid) return; DWORD remain = cooldownRemain(lastKillTick, now, RISK_COOLDOWN_MS);
            if (remain) {
                if (++killCooldownHits <= ABUSE_THRESHOLD) {
                    SendUtf8(L"RESULT", L"KILL_PROCESS COOLDOWN " + std::to_wstring(remain) + L"ms");
                }
                return;
            }
            lastKillTick = now; killCooldownHits = 0; KillProcessByPid(pid); SendUtf8(L"RESULT", L"KILL_PROCESS OK " + std::to_wstring(pid));
        }
        else if (cmd == "QUARANTINE_FILE") {
            std::string rest; getline(iss,rest); if(!rest.empty()&&rest[0]==' ')rest.erase(0,1); if(rest.empty()) return; auto w = Utf8ToWide(rest); DWORD remain = cooldownRemain(lastQuarantineTick, now, RISK_COOLDOWN_MS);
            if (remain) {
                if (++quarantineCooldownHits <= ABUSE_THRESHOLD) {
                    SendUtf8(L"RESULT", L"QUARANTINE_FILE COOLDOWN " + std::to_wstring(remain) + L"ms");
                }
                return;
            }
            lastQuarantineTick = now; quarantineCooldownHits = 0; QuarantineFile(w); SendUtf8(L"RESULT", L"QUARANTINE_FILE OK");
        }
        else if (cmd == "REQUEST_HEARTBEAT_NOW") { Heartbeat::Instance().TriggerNow(); }
    else if (cmd == "PROLOG_ADD_TARGET") { std::string mod, fn; size_t bytes=8; iss>>mod>>fn>>bytes; if(!mod.empty()&&!fn.empty()) PrologHookChecker::Instance().AddTarget(Utf8ToWide(mod),fn,bytes); }
        else if (cmd == "PROLOG_REBASELINE") { PrologHookChecker::Instance().Rebaseline(); }
        else if (cmd == "PROLOG_LIST") { auto targets = PrologHookChecker::Instance().GetTargets(); SendUtf8(L"PROLOG", L"BEGIN_PROLOG_LIST count=" + std::to_wstring(targets.size())); for (auto& t : targets) { std::wstring lineW = t.module + L" " + std::wstring(t.function.begin(), t.function.end()) + L" " + std::to_wstring(t.minBytes); SendUtf8(L"PROLOG", lineW); } SendUtf8(L"PROLOG", L"END_PROLOG_LIST"); }
        else if (cmd == "PIPE_SET_XOR_KEY") { unsigned int k=0; iss>>std::hex>>k; if(k<=0xFF) PipeClient::Instance().RotateXorKey((uint8_t)k,true); }
        else if (cmd == "HEARTBEAT_ADAPTIVE_ON") { Heartbeat::Instance().EnableAdaptive(true); }
        else if (cmd == "HEARTBEAT_ADAPTIVE_OFF") { Heartbeat::Instance().EnableAdaptive(false); }
        else if (cmd == "PIPE_SET_CRC_ON") { PipeClient::Instance().SetCrcEnabled(true); }
        else if (cmd == "PIPE_SET_CRC_OFF") { PipeClient::Instance().SetCrcEnabled(false); }
        else if (cmd == "PIPE_ROLLING_XOR_ON") { PipeClient::Instance().SetRollingXorEnabled(true); }
        else if (cmd == "PIPE_ROLLING_XOR_OFF") { PipeClient::Instance().SetRollingXorEnabled(false); }
    else if (cmd == "POLICY_LOAD") { std::string rest; getline(iss,rest); if(!rest.empty()&&rest[0]==' ')rest.erase(0,1); if(!rest.empty()) PolicyManager::LoadPolicy(Utf8ToWide(rest)); }
    else if (cmd == "POLICY_SAVE") { std::string rest; getline(iss,rest); if(!rest.empty()&&rest[0]==' ')rest.erase(0,1); if(!rest.empty()) PolicyManager::SavePolicy(Utf8ToWide(rest)); }
    else if (cmd == "WHITELIST_CHUNK_ADD") { std::string mod; size_t idx; iss>>mod>>idx; if(!mod.empty()) IntegrityChunkWhitelist::Add(Utf8ToWide(mod), idx); }
        else if (cmd == "RESET_PROFILER") { DetectorScheduler::Instance().ResetProfiles(); }
    else if (cmd == "SET_INTERVAL") { std::string det; unsigned ms=0; iss>>det>>ms; if(!det.empty()&&ms>0) { bool changed = DetectorScheduler::Instance().SetIntervalOverride(Utf8ToWide(det), ms); SendUtf8(L"RESULT", changed ? (L"SET_INTERVAL OK " + Utf8ToWide(det) + L"=" + std::to_wstring(ms)) : (L"SET_INTERVAL FAIL " + Utf8ToWide(det))); } }
    else if (cmd == "CLEAR_INTERVAL") { std::string det; iss>>det; if(!det.empty()) { bool ok = DetectorScheduler::Instance().ClearIntervalOverride(Utf8ToWide(det)); SendUtf8(L"RESULT", ok? (L"CLEAR_INTERVAL OK "+Utf8ToWide(det)) : (L"CLEAR_INTERVAL FAIL "+Utf8ToWide(det))); } }
        else if (cmd == "CLEAR_INTERVAL_ALL") { DetectorScheduler::Instance().ClearAllIntervalOverrides(); SendUtf8(L"RESULT", L"CLEAR_INTERVAL_ALL OK"); }
    else if (cmd == "LIST_INTERVALS") { auto all = DetectorScheduler::Instance().GetAllIntervals(); std::wstring w; for (size_t i=0;i<all.size();++i){ if(i) w+=L","; w += all[i].name + L"=" + std::to_wstring(all[i].intervalMs); if(all[i].overridden) w += L"*"; } SendUtf8(L"INTERVALS", w); }
    else if (cmd == "SELFTEST") { auto res = DetectorScheduler::Instance().RunSelfTest(); std::wstring w; for(size_t i=0;i<res.size();++i){ if(i) w+=L","; w+=res[i].name + L"=" + (res[i].durationMs>=0? std::to_wstring((int)res[i].durationMs)+L"ms":L"ERR"); } SendUtf8(L"SELFTEST", w); }
    else if (cmd == "PROFILER_DETAIL") { auto det = DetectorScheduler::Instance().GetProfilerDetails(); std::wstring w; for(size_t i=0;i<det.size();++i){ if(i) w+=L";"; const auto& d=det[i]; w+=d.name+L",run="+std::to_wstring(d.runCount)+L",last="+std::to_wstring((int)d.lastMs)+L"ms,avg="+std::to_wstring((int)d.avgMs)+L"ms,int="+std::to_wstring(d.interval)+L"(base="+std::to_wstring(d.baseInterval)+L")"+(d.overridden?L"*":(d.adaptive?L"~":L"")); } SendUtf8(L"PROFILER_DETAIL", w); }
    else if (cmd == "QUEUE_DUMP") { auto q = DetectorScheduler::Instance().GetQueueSnapshot(); std::wstring w; for(size_t i=0;i<q.size();++i){ if(i) w+=L","; w+=q[i].name+L"="+std::to_wstring(q[i].remainingMs)+L"ms/"+std::to_wstring(q[i].intervalMs)+L"ms"+(q[i].overridden?L"*":(q[i].adaptive?L"~":L"")); } SendUtf8(L"QUEUE_DUMP", w); }
    else if (cmd == "SIGNATURE_LIST") { auto &sigs = GetSignatures(); std::wstring w; for (size_t i=0;i<sigs.size(); ++i){ if(i) w+=L"|"; w += sigs[i].name + L"(" + std::to_wstring(sigs[i].bytes.size()) + L")"; } if(w.empty()) w=L"<empty>"; SendUtf8(L"SIGNATURE_LIST", w); }
    else if (cmd == "CORR_STATUS") { auto w = DetectionCorrelator::Instance().GetStatus(); SendUtf8(L"CORR_STATUS", w); }
    else if (cmd == "CORR_STATUS_JSON") { auto j = DetectionCorrelator::Instance().GetStatusJson(); SendUtf8(L"CORR_STATUS_JSON", std::wstring(j.begin(), j.end())); }
    else if (cmd == "CORR_RESET") { DetectionCorrelator::Instance().Reset(); SendUtf8(L"CORR_RESET", L"OK"); }
    else if (cmd == "DUMP_CONFIG") {
        std::wstringstream ss;
        ss << L"CMD_WINDOW_MS=" << Config::CMD_WINDOW_MS
           << L",CMD_MAX_RECENT=" << Config::CMD_MAX_RECENT
           << L",CMD_RISK_COOLDOWN_MS=" << Config::CMD_RISK_COOLDOWN_MS
           << L",CMD_ABUSE_THRESHOLD=" << Config::CMD_ABUSE_THRESHOLD
           << L",ADAPT_INCREASE_THRESHOLD=" << (int)Config::ADAPT_INCREASE_THRESHOLD
           << L",ADAPT_DECREASE_THRESHOLD=" << (int)Config::ADAPT_DECREASE_THRESHOLD
           << L",ADAPT_INTERVAL_MULT_MAX=" << Config::ADAPT_INTERVAL_MULT_MAX
           << L",SCHED_MIN_SLEEP_MS=" << Config::SCHED_MIN_SLEEP_MS
           << L",DEFAULT_SLOW_THRESHOLD_MS=" << (int)Config::DEFAULT_SLOW_THRESHOLD_MS
           << L",DEFAULT_SLOW_ALERT_STREAK=" << Config::DEFAULT_SLOW_ALERT_STREAK
           << L",PROC_WATCH_POLL_IDLE_MS=" << Config::PROC_WATCH_POLL_IDLE_MS
           << L",PROC_WATCH_POLL_ACTIVE_MS=" << Config::PROC_WATCH_POLL_ACTIVE_MS
           << L",PIPE_RECONNECT_MS=" << Config::PIPE_RECONNECT_MS
           << L",PIPE_IDLE_SLEEP_MS=" << Config::PIPE_IDLE_SLEEP_MS
           << L",TCP_IDLE_SLEEP_MS=" << Config::TCP_IDLE_SLEEP_MS
           << L",PIPE_CMD_BUFFER=" << Config::PIPE_CMD_BUFFER
           << L",TCP_HOST_MAX=" << Config::TCP_HOST_MAX
           << L",MODULE_ENUM_MAX=" << Config::MODULE_ENUM_MAX
           << L",PROCESS_ENUM_RESERVE=" << Config::PROCESS_ENUM_RESERVE
           << L",WINDOW_TITLE_MAX=" << Config::WINDOW_TITLE_MAX
           << L",CHUNK_SIZE=" << Config::CHUNK_SIZE
           << L",SIGNATURE_SCAN_MAX=" << Config::SIGNATURE_SCAN_MAX
           << L",CAPTURE_MAX=" << Config::CAPTURE_MAX
           << L",CE_MIN_WIDTH=" << Config::CE_MIN_WIDTH
           << L",CE_MIN_HEIGHT=" << Config::CE_MIN_HEIGHT
           << L",CE_SCORE_THRESHOLD=" << Config::CE_SCORE_THRESHOLD
           << L",CE_COOLDOWN_MS=" << Config::CE_COOLDOWN_MS
           << L",CE_REQ_LISTS=" << Config::CE_REQ_LISTS
           << L",CE_REQ_EDITS=" << Config::CE_REQ_EDITS
           << L",CE_UI_HITS_SCORE1=" << Config::CE_UI_HITS_SCORE1
           << L",CE_UI_HITS_SCORE2=" << Config::CE_UI_HITS_SCORE2
           << L",CE_EARLYSTOP_UI=" << Config::CE_EARLYSTOP_UI
           << L",CE_EARLYSTOP_LISTS=" << Config::CE_EARLYSTOP_LISTS
           << L",CE_EARLYSTOP_EDITS=" << Config::CE_EARLYSTOP_EDITS;
              ss << L",CORR_WINDOW_MS=" << Config::CORR_WINDOW_MS
                  << L",CORR_PRUNE_INTERVAL_MS=" << Config::CORR_PRUNE_INTERVAL_MS
                  << L",CORR_SCORE_THRESHOLD=" << Config::CORR_SCORE_THRESHOLD
                  << L",CORR_TRIGGER_DISTINCT=" << Config::CORR_TRIGGER_DISTINCT
                  << L",CE_PARTIAL_SCORE=" << Config::CE_PARTIAL_SCORE
                  << L",SIG_PARTIAL_SCORE=" << Config::SIG_PARTIAL_SCORE
                  << L",EXT_HANDLE_SCORE=" << Config::EXT_HANDLE_SCORE;
        SendUtf8(L"CONFIG", ss.str());
    }
    else if (cmd == "GET_STATUS") { auto snap = RuntimeStats::Instance().GetSnapshot(); auto profiles = DetectorScheduler::Instance().GetProfiles(); std::wstring w = L"detections=" + std::to_wstring(snap.detections) + L" info=" + std::to_wstring(snap.infoEvents) + L" heartbeats=" + std::to_wstring(snap.heartbeats) + L" uptime_sec=" + std::to_wstring(snap.lastUptimeSec); w += L" profiler="; size_t shown=0; for (size_t i=0;i<profiles.size();++i){ if (profiles[i].runCount==0) continue; if(shown) w+=L","; w += profiles[i].name + L":" + std::to_wstring((int)profiles[i].avgDurationMs) + L"ms"; if(++shown>=10) break; } SendUtf8(L"STATUS", w); }
    }

    void PipeCommandClient::WorkerLoop() { Log(L"PipeCommandClient start"); char buffer[OblivionEye::Config::PIPE_CMD_BUFFER]; while (m_running) { EnsureConnected(); if (g_hCmdPipe == INVALID_HANDLE_VALUE) { std::this_thread::sleep_for(std::chrono::milliseconds(1000)); continue; } DWORD read=0; BOOL ok=ReadFile(g_hCmdPipe, buffer, sizeof(buffer)-1, &read, nullptr); if (!ok || read==0) { ClosePipe(); std::this_thread::sleep_for(std::chrono::milliseconds(500)); continue; } buffer[read]='\0'; HandleCommandLine(std::string(buffer)); } ClosePipe(); Log(L"PipeCommandClient stop"); }
}
