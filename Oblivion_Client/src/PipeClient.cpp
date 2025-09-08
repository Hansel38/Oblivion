#include "../pch.h"
#include "../include/PipeClient.h"
#include "../include/Logger.h"
#include <windows.h>
#include <thread>
#include <mutex>
#include <queue>
#include <string>

namespace OblivionEye {

    static HANDLE g_hPipe = INVALID_HANDLE_VALUE;
    static std::mutex g_qMtx;
    static std::queue<std::string> g_queue;

    PipeClient& PipeClient::Instance() { static PipeClient s; return s; }

    void PipeClient::Start(const std::wstring& pipeName) {
        if (m_running.exchange(true)) return;
        m_pipeName = pipeName;
        std::thread([this]() { WorkerLoop(); }).detach();
    }

    void PipeClient::Stop() {
        m_running = false;
        ClosePipe();
    }

    void PipeClient::Enqueue(const std::string& msg) {
        std::lock_guard<std::mutex> lk(g_qMtx);
        g_queue.push(msg);
    }

    void PipeClient::Send(const std::wstring& msg) {
        int len = WideCharToMultiByte(CP_UTF8, 0, msg.c_str(), -1, nullptr, 0, nullptr, nullptr);
        std::string utf8(len, '\0');
        WideCharToMultiByte(CP_UTF8, 0, msg.c_str(), -1, &utf8[0], len, nullptr, nullptr);
        Enqueue(utf8);
    }

    void PipeClient::Send(const std::string& msg) {
        Enqueue(msg);
    }

    void PipeClient::ClosePipe() {
        if (g_hPipe != INVALID_HANDLE_VALUE) {
            CloseHandle(g_hPipe);
            g_hPipe = INVALID_HANDLE_VALUE;
        }
    }

    void PipeClient::EnsureConnected() {
        if (g_hPipe != INVALID_HANDLE_VALUE) return;
        g_hPipe = CreateFileW(m_pipeName.c_str(), GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (g_hPipe == INVALID_HANDLE_VALUE) {
            // Server belum ada. Biarkan worker retry.
        } else {
            Log(L"PipeClient connected");
        }
    }

    void PipeClient::WorkerLoop() {
        Log(L"PipeClient start");
        while (m_running) {
            EnsureConnected();
            if (g_hPipe == INVALID_HANDLE_VALUE) {
                std::this_thread::sleep_for(std::chrono::milliseconds(2000));
                continue;
            }
            std::string msg;
            {
                std::lock_guard<std::mutex> lk(g_qMtx);
                if (!g_queue.empty()) { msg = g_queue.front(); g_queue.pop(); }
            }
            if (!msg.empty()) {
                DWORD written = 0;
                BOOL ok = WriteFile(g_hPipe, msg.c_str(), (DWORD)msg.size(), &written, nullptr);
                if (!ok) {
                    ClosePipe();
                }
            } else {
                std::this_thread::sleep_for(std::chrono::milliseconds(200));
            }
        }
        ClosePipe();
        Log(L"PipeClient stop");
    }
}
