#include "../pch.h"
#include "../include/TcpClient.h"
#include "../include/Logger.h"
#include "../include/Config.h"
#include "../include/StringUtil.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <thread>
#include <queue>
#include <mutex>

#pragma comment(lib, "ws2_32.lib")

namespace OblivionEye {
namespace {
    std::mutex g_plainMtx;
    std::queue<std::string> g_plainQ;
}

// ================= PlainTelemetryTransport =================
bool PlainTelemetryTransport::Start(const std::wstring& host, unsigned short port){
    if (m_running.exchange(true)) return true; // already running
    std::thread([this, host, port]() { Worker(host, port); }).detach();
    return true;
}
void PlainTelemetryTransport::Stop(){ m_running = false; }
void PlainTelemetryTransport::Enqueue(const std::string& msg){ std::lock_guard<std::mutex> lk(g_plainMtx); g_plainQ.push(msg); }
void PlainTelemetryTransport::Send(const std::string& line){ Enqueue(line); }
void PlainTelemetryTransport::Worker(const std::wstring& host, unsigned short port){
    Log(L"PlainTelemetryTransport start");
    WSADATA wsa; WSAStartup(MAKEWORD(2,2), &wsa);
    auto hostUtf8Str = StringUtil::WideToUtf8(host);
    if(hostUtf8Str.size() >= Config::TCP_HOST_MAX) hostUtf8Str.resize(Config::TCP_HOST_MAX-1);
    char hostUtf8[Config::TCP_HOST_MAX] = {0}; memcpy(hostUtf8, hostUtf8Str.c_str(), hostUtf8Str.size());
    while(m_running){
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if(s==INVALID_SOCKET){ std::this_thread::sleep_for(std::chrono::seconds(2)); continue; }
        sockaddr_in addr{}; addr.sin_family=AF_INET; addr.sin_port=htons(port); inet_pton(AF_INET, hostUtf8, &addr.sin_addr);
        if(connect(s,(sockaddr*)&addr,sizeof(addr))==SOCKET_ERROR){ closesocket(s); std::this_thread::sleep_for(std::chrono::seconds(2)); continue; }
        Log(L"PlainTelemetryTransport connected");
        for(;;){
            std::string msg; {
                std::lock_guard<std::mutex> lk(g_plainMtx);
                if(!g_plainQ.empty()){ msg = g_plainQ.front(); g_plainQ.pop(); }
            }
            if(!m_running) break;
            if(!msg.empty()){
                int sent = send(s, msg.c_str(), (int)msg.size(), 0);
                if(sent==SOCKET_ERROR) break;
            } else {
                std::this_thread::sleep_for(std::chrono::milliseconds(Config::TCP_IDLE_SLEEP_MS));
            }
        }
        closesocket(s);
    }
    WSACleanup();
    Log(L"PlainTelemetryTransport stop");
}

// ================= TcpClient facade =================
TcpClient::TcpClient(){ m_transport = new PlainTelemetryTransport(); }
TcpClient& TcpClient::Instance(){ static TcpClient s; return s; }
void TcpClient::Start(const std::wstring& host, unsigned short port){ if(m_transport) m_transport->Start(host, port); }
void TcpClient::Stop(){ if(m_transport) m_transport->Stop(); }
void TcpClient::Send(const std::string& msg){ if(m_transport) m_transport->Send(msg); }
bool TcpClient::IsRunning() const { return m_transport && m_transport->IsRunning(); }
void TcpClient::UseTls(bool enable){ m_tlsRequested = enable; /* skeleton: implement switch to TLS transport nanti */ }
bool TcpClient::IsTls() const { return m_transport && m_transport->IsTls(); }
}
