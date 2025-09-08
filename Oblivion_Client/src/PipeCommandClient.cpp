#include "../pch.h"
#include "../include/PipeCommandClient.h"
#include "../include/Logger.h"
#include "../include/Blacklist.h"
#include "../include/ModuleBlacklist.h"
#include "../include/Heartbeat.h"
#include "../include/OverlayBlacklist.h"
#include "../include/DriverBlacklist.h"
#include <windows.h>
#include <thread>
#include <string>
#include <sstream>

namespace OblivionEye {

    static HANDLE g_hCmdPipe = INVALID_HANDLE_VALUE;

    PipeCommandClient& PipeCommandClient::Instance() { static PipeCommandClient s; return s; }

    void PipeCommandClient::Start(const std::wstring& pipeName) {
        if (m_running.exchange(true)) return;
        m_pipeName = pipeName;
        std::thread([this]() { WorkerLoop(); }).detach();
    }

    void PipeCommandClient::Stop() {
        m_running = false;
        ClosePipe();
    }

    void PipeCommandClient::ClosePipe() {
        if (g_hCmdPipe != INVALID_HANDLE_VALUE) {
            CloseHandle(g_hCmdPipe);
            g_hCmdPipe = INVALID_HANDLE_VALUE;
        }
    }

    void PipeCommandClient::EnsureConnected() {
        if (g_hCmdPipe != INVALID_HANDLE_VALUE) return;
        g_hCmdPipe = CreateFileW(m_pipeName.c_str(), GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (g_hCmdPipe == INVALID_HANDLE_VALUE) {
            // server belum siap
        } else {
            Log(L"PipeCommandClient connected");
        }
    }

    void PipeCommandClient::HandleCommandLine(const std::string& line) {
        std::istringstream iss(line);
        std::string cmd; iss >> cmd;
        if (cmd == "CLOSE_CLIENT") {
            ExitProcess(0);
        } else if (cmd == "UPDATE_BLACKLIST") {
            std::string name; iss >> name; // proses name
            if (!name.empty()) {
                // convert to wide
                int len = MultiByteToWideChar(CP_UTF8, 0, name.c_str(), -1, nullptr, 0);
                std::wstring wname(len, L'\0');
                MultiByteToWideChar(CP_UTF8, 0, name.c_str(), -1, &wname[0], len);
                if (!wname.empty() && wname.back() == L'\0') wname.pop_back();
                AddBlacklistedProcessName(wname);
                Log(L"Process blacklist updated: " + wname);
            }
        } else if (cmd == "UPDATE_MODULE_BLACKLIST") {
            std::string name; iss >> name; // module name
            if (!name.empty()) {
                // convert to wide
                int len = MultiByteToWideChar(CP_UTF8, 0, name.c_str(), -1, nullptr, 0);
                std::wstring wname(len, L'\0');
                MultiByteToWideChar(CP_UTF8, 0, name.c_str(), -1, &wname[0], len);
                if (!wname.empty() && wname.back() == L'\0') wname.pop_back();
                AddBlacklistedModuleName(wname);
                Log(L"Module blacklist updated: " + wname);
            }
        } else if (cmd == "UPDATE_OVERLAY_BLACKLIST_TITLE") {
            std::string t; getline(iss, t);
            if (!t.empty() && t[0] == ' ') t.erase(0,1);
            if (!t.empty()) {
                // convert to wide
                int len = MultiByteToWideChar(CP_UTF8, 0, t.c_str(), -1, nullptr, 0);
                std::wstring wt(len, L'\0');
                MultiByteToWideChar(CP_UTF8, 0, t.c_str(), -1, &wt[0], len);
                if (!wt.empty() && wt.back() == L'\0') wt.pop_back();
                AddBlacklistedWindowTitle(wt);
                Log(L"Overlay title blacklist updated: " + wt);
            }
        } else if (cmd == "UPDATE_OVERLAY_BLACKLIST_CLASS") {
            std::string c; getline(iss, c);
            if (!c.empty() && c[0] == ' ') c.erase(0,1);
            if (!c.empty()) {
                // convert to wide
                int len = MultiByteToWideChar(CP_UTF8, 0, c.c_str(), -1, nullptr, 0);
                std::wstring wc(len, L'\0');
                MultiByteToWideChar(CP_UTF8, 0, c.c_str(), -1, &wc[0], len);
                if (!wc.empty() && wc.back() == L'\0') wc.pop_back();
                AddBlacklistedWindowClass(wc);
                Log(L"Overlay class blacklist updated: " + wc);
            }
        } else if (cmd == "UPDATE_DRIVER_BLACKLIST") {
            std::string name; iss >> name; // driver base name
            if (!name.empty()) {
                // convert to wide
                int len = MultiByteToWideChar(CP_UTF8, 0, name.c_str(), -1, nullptr, 0);
                std::wstring wname(len, L'\0');
                MultiByteToWideChar(CP_UTF8, 0, name.c_str(), -1, &wname[0], len);
                if (!wname.empty() && wname.back() == L'\0') wname.pop_back();
                AddBlacklistedDriverName(wname);
                Log(L"Driver blacklist updated: " + wname);
            }
        } else if (cmd == "REQUEST_HEARTBEAT_NOW") {
            // Kirim 1 tick heartbeat segera (reuse logger & event reporter di modul Heartbeat)
            Log(L"Heartbeat requested by server");
            Heartbeat::Instance().TriggerNow();
        }
    }

    void PipeCommandClient::WorkerLoop() {
        Log(L"PipeCommandClient start");
        char buffer[1024];
        while (m_running) {
            EnsureConnected();
            if (g_hCmdPipe == INVALID_HANDLE_VALUE) { std::this_thread::sleep_for(std::chrono::milliseconds(1000)); continue; }
            DWORD read = 0;
            BOOL ok = ReadFile(g_hCmdPipe, buffer, sizeof(buffer)-1, &read, nullptr);
            if (!ok || read == 0) {
                ClosePipe();
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
                continue;
            }
            buffer[read] = '\0';
            HandleCommandLine(std::string(buffer));
        }
        ClosePipe();
        Log(L"PipeCommandClient stop");
    }
}
