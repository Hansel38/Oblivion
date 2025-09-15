#include "../pch.h"
#include "../include/TcpClient.h"
#include "../include/Logger.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include "../include/Config.h"
#include "../include/StringUtil.h"
#include <thread>
#include <queue>
#include <mutex>

#pragma comment(lib, "ws2_32.lib")

namespace OblivionEye {
namespace {
    std::mutex g_mtx;
    std::queue<std::string> g_q;
}

TcpClient& TcpClient::Instance() { static TcpClient s; return s; }

void TcpClient::Start(const std::wstring& host, unsigned short port) {
    if (m_running.exchange(true)) return;
    std::thread([this, host, port]() { Worker(host, port); }).detach();
}

void TcpClient::Stop() { m_running = false; }

void TcpClient::Enqueue(const std::string& msg) {
    std::lock_guard<std::mutex> lk(g_mtx); g_q.push(msg);
}

void TcpClient::Send(const std::string& msg) { Enqueue(msg); }

void TcpClient::Worker(const std::wstring& host, unsigned short port) {
    Log(L"TcpClient start");
    WSADATA wsa; WSAStartup(MAKEWORD(2, 2), &wsa);
    auto hostUtf8Str = StringUtil::WideToUtf8(host);
    if (hostUtf8Str.size() >= OblivionEye::Config::TCP_HOST_MAX)
        hostUtf8Str.resize(OblivionEye::Config::TCP_HOST_MAX - 1);
    char hostUtf8[OblivionEye::Config::TCP_HOST_MAX] = {0};
    memcpy(hostUtf8, hostUtf8Str.c_str(), hostUtf8Str.size());

    while (m_running) {
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) { std::this_thread::sleep_for(std::chrono::seconds(2)); continue; }

        sockaddr_in addr{}; addr.sin_family = AF_INET; addr.sin_port = htons(port);
        inet_pton(AF_INET, hostUtf8, &addr.sin_addr);

        if (connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
            closesocket(s); std::this_thread::sleep_for(std::chrono::seconds(2)); continue; }

        Log(L"TcpClient connected");
        for (;;) {
            std::string msg;
            {
                std::lock_guard<std::mutex> lk(g_mtx);
                if (!g_q.empty()) { msg = g_q.front(); g_q.pop(); }
            }
            if (!m_running) break;
            if (!msg.empty()) {
                int sent = send(s, msg.c_str(), static_cast<int>(msg.size()), 0);
                if (sent == SOCKET_ERROR) break;
            } else {
                std::this_thread::sleep_for(std::chrono::milliseconds(Config::TCP_IDLE_SLEEP_MS));
            }
        }
        closesocket(s);
    }
    WSACleanup();
    Log(L"TcpClient stop");
}
}
