#pragma once
#include <string>
#include <atomic>

namespace OblivionEye {
    class TcpClient {
    public:
        static TcpClient& Instance();
        void Start(const std::wstring& host, unsigned short port);
        void Stop();
        void Send(const std::string& msg);
    private:
        TcpClient() = default;
        void Worker(const std::wstring& host, unsigned short port);
        void Enqueue(const std::string& msg);
        std::atomic<bool> m_running{ false };
    };
}
