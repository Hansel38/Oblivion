#include "../pch.h"
#include "../include/PipeCommandClient.h"
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
#include <windows.h>
#include <thread>
#include <string>
#include <sstream>

namespace OblivionEye {

    static HANDLE g_hCmdPipe = INVALID_HANDLE_VALUE;

    PipeCommandClient& PipeCommandClient::Instance() { static PipeCommandClient s; return s; }

    void PipeCommandClient::Start(const std::wstring& pipeName) { if (m_running.exchange(true)) return; m_pipeName = pipeName; std::thread([this]() { WorkerLoop(); }).detach(); }
    void PipeCommandClient::Stop() { m_running = false; ClosePipe(); }
    void PipeCommandClient::ClosePipe() { if (g_hCmdPipe != INVALID_HANDLE_VALUE) { CloseHandle(g_hCmdPipe); g_hCmdPipe = INVALID_HANDLE_VALUE; } }
    void PipeCommandClient::EnsureConnected() { if (g_hCmdPipe != INVALID_HANDLE_VALUE) return; g_hCmdPipe = CreateFileW(m_pipeName.c_str(), GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr); if (g_hCmdPipe != INVALID_HANDLE_VALUE) Log(L"PipeCommandClient connected"); }

    static std::wstring Utf8ToW(const std::string& s) { if (s.empty()) return L""; int len=MultiByteToWideChar(CP_UTF8,0,s.c_str(),-1,nullptr,0); if(len<=0) return L""; std::wstring w(len,L'\0'); MultiByteToWideChar(CP_UTF8,0,s.c_str(),-1,&w[0],len); if(!w.empty()&&w.back()==L'\0') w.pop_back(); return w; }
    static void KillProcessByPid(DWORD pid) { HANDLE h=OpenProcess(PROCESS_TERMINATE,FALSE,pid); if(!h) return; TerminateProcess(h,0); CloseHandle(h);}    
    static void QuarantineFile(const std::wstring& path) { if(path.empty()) return; std::wstring newPath=path+L".quarantine"; MoveFileExW(path.c_str(),newPath.c_str(),MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH);}    

    static void SendUtf8Line(const std::wstring& w) {
        if (!PipeClient::Instance().IsRunning()) return;
        int len = WideCharToMultiByte(CP_UTF8,0,w.c_str(),-1,nullptr,0,nullptr,nullptr);
        std::string utf8(len,'\0');
        WideCharToMultiByte(CP_UTF8,0,w.c_str(),-1,&utf8[0],len,nullptr,nullptr);
        if(!utf8.empty() && utf8.back()=='\0') utf8.pop_back();
        PipeClient::Instance().Send("INFO|PROLOG|" + utf8);
    }

    void PipeCommandClient::HandleCommandLine(const std::string& line) {
        std::istringstream iss(line); std::string cmd; iss >> cmd;
        if (cmd == "CLOSE_CLIENT") { ExitProcess(0); }
        else if (cmd == "UPDATE_BLACKLIST") { std::string name; iss>>name; if(!name.empty()) AddBlacklistedProcessName(Utf8ToW(name)); }
        else if (cmd == "UPDATE_MODULE_BLACKLIST") { std::string name; iss>>name; if(!name.empty()) AddBlacklistedModuleName(Utf8ToW(name)); }
        else if (cmd == "UPDATE_OVERLAY_BLACKLIST_TITLE") { std::string rest; getline(iss,rest); if(!rest.empty()&&rest[0]==' ')rest.erase(0,1); if(!rest.empty()) AddBlacklistedWindowTitle(Utf8ToW(rest)); }
        else if (cmd == "UPDATE_OVERLAY_BLACKLIST_CLASS") { std::string rest; getline(iss,rest); if(!rest.empty()&&rest[0]==' ')rest.erase(0,1); if(!rest.empty()) AddBlacklistedWindowClass(Utf8ToW(rest)); }
        else if (cmd == "UPDATE_DRIVER_BLACKLIST") { std::string name; iss>>name; if(!name.empty()) AddBlacklistedDriverName(Utf8ToW(name)); }
        else if (cmd == "WHITELIST_PUBLISHER_ADD") { std::string rest; getline(iss,rest); if(!rest.empty()&&rest[0]==' ')rest.erase(0,1); if(!rest.empty()) PublisherWhitelist::AddTrusted(Utf8ToW(rest)); }
        else if (cmd == "WHITELIST_FILE_ADD") { std::string rest; getline(iss,rest); if(!rest.empty()&&rest[0]==' ')rest.erase(0,1); if(!rest.empty()) DigitalSignatureScanner::Instance().AddCriticalPath(Utf8ToW(rest)); }
        else if (cmd == "KILL_PROCESS") { DWORD pid=0; iss>>pid; if(pid) KillProcessByPid(pid); }
        else if (cmd == "QUARANTINE_FILE") { std::string rest; getline(iss,rest); if(!rest.empty()&&rest[0]==' ')rest.erase(0,1); if(!rest.empty()) QuarantineFile(Utf8ToW(rest)); }
        else if (cmd == "REQUEST_HEARTBEAT_NOW") { Heartbeat::Instance().TriggerNow(); }
        else if (cmd == "PROLOG_ADD_TARGET") { std::string mod, fn; size_t bytes=8; iss>>mod>>fn>>bytes; if(!mod.empty()&&!fn.empty()) PrologHookChecker::Instance().AddTarget(Utf8ToW(mod),fn,bytes); }
        else if (cmd == "PROLOG_REBASELINE") { PrologHookChecker::Instance().Rebaseline(); }
        else if (cmd == "PROLOG_LIST") { auto targets = PrologHookChecker::Instance().GetTargets(); SendUtf8Line(L"BEGIN_PROLOG_LIST count=" + std::to_wstring(targets.size())); for (auto& t : targets) { std::wstring lineW = t.module + L" " + std::wstring(t.function.begin(), t.function.end()) + L" " + std::to_wstring(t.minBytes); SendUtf8Line(lineW); } SendUtf8Line(L"END_PROLOG_LIST"); }
        else if (cmd == "PIPE_SET_XOR_KEY") { unsigned int k=0; iss>>std::hex>>k; if(k<=0xFF) PipeClient::Instance().RotateXorKey((uint8_t)k,true); }
        else if (cmd == "HEARTBEAT_ADAPTIVE_ON") { Heartbeat::Instance().EnableAdaptive(true); }
        else if (cmd == "HEARTBEAT_ADAPTIVE_OFF") { Heartbeat::Instance().EnableAdaptive(false); }
        else if (cmd == "PIPE_SET_CRC_ON") { PipeClient::Instance().SetCrcEnabled(true); }
        else if (cmd == "PIPE_SET_CRC_OFF") { PipeClient::Instance().SetCrcEnabled(false); }
        else if (cmd == "PIPE_ROLLING_XOR_ON") { PipeClient::Instance().SetRollingXorEnabled(true); }
        else if (cmd == "PIPE_ROLLING_XOR_OFF") { PipeClient::Instance().SetRollingXorEnabled(false); }
        else if (cmd == "POLICY_LOAD") { std::string rest; getline(iss,rest); if(!rest.empty()&&rest[0]==' ')rest.erase(0,1); if(!rest.empty()) PolicyManager::LoadPolicy(Utf8ToW(rest)); }
        else if (cmd == "POLICY_SAVE") { std::string rest; getline(iss,rest); if(!rest.empty()&&rest[0]==' ')rest.erase(0,1); if(!rest.empty()) PolicyManager::SavePolicy(Utf8ToW(rest)); }
        else if (cmd == "WHITELIST_CHUNK_ADD") { std::string mod; size_t idx; iss>>mod>>idx; if(!mod.empty()) IntegrityChunkWhitelist::Add(Utf8ToW(mod), idx); }
        else if (cmd == "GET_STATUS") { auto snap = RuntimeStats::Instance().GetSnapshot(); std::wstring w = L"STATUS detections=" + std::to_wstring(snap.detections) + L" info=" + std::to_wstring(snap.infoEvents) + L" heartbeats=" + std::to_wstring(snap.heartbeats) + L" uptime_sec=" + std::to_wstring(snap.lastUptimeSec); if (PipeClient::Instance().IsRunning()) { int len=WideCharToMultiByte(CP_UTF8,0,w.c_str(),-1,nullptr,0,nullptr,nullptr); std::string utf8(len,'\0'); WideCharToMultiByte(CP_UTF8,0,w.c_str(),-1,&utf8[0],len,nullptr,nullptr); if(!utf8.empty()&&utf8.back()=='\0') utf8.pop_back(); PipeClient::Instance().Send("INFO|STATUS|" + utf8); } }
    }

    void PipeCommandClient::WorkerLoop() { Log(L"PipeCommandClient start"); char buffer[1024]; while (m_running) { EnsureConnected(); if (g_hCmdPipe == INVALID_HANDLE_VALUE) { std::this_thread::sleep_for(std::chrono::milliseconds(1000)); continue; } DWORD read=0; BOOL ok=ReadFile(g_hCmdPipe, buffer, sizeof(buffer)-1, &read, nullptr); if (!ok || read==0) { ClosePipe(); std::this_thread::sleep_for(std::chrono::milliseconds(500)); continue; } buffer[read]='\0'; HandleCommandLine(std::string(buffer)); } ClosePipe(); Log(L"PipeCommandClient stop"); }
}
