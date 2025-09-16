#pragma once
#include <string>
#include <atomic>
#include "TelemetryTransport.h"

namespace OblivionEye {
    // Plain socket transport (no TLS) internal implementation
    class PlainTelemetryTransport : public ITelemetryTransport {
    public:
        PlainTelemetryTransport() = default;
        bool Start(const std::wstring& host, unsigned short port) override;
        void Stop() override;
        void Send(const std::string& line) override; // append newline if not present
        bool IsRunning() const override { return m_running.load(); }
        bool IsTls() const override { return false; }
    private:
        void Worker(const std::wstring& host, unsigned short port);
        void Enqueue(const std::string& msg);
        std::atomic<bool> m_running{ false };
    };

    // Facade lama agar kode lain tetap memakai TcpClient::Instance()
    class TcpClient {
    public:
        static TcpClient& Instance();
        void Start(const std::wstring& host, unsigned short port);
        void Stop();
        void Send(const std::string& msg);
        bool IsRunning() const;
        // Future: ganti implementasi dengan TLS secara dinamis
        void UseTls(bool enable); // stub (akan diisi setelah TLS skeleton)
        bool IsTls() const;
    private:
        TcpClient();
        ITelemetryTransport* m_transport; // owned simple
        bool m_tlsRequested=false; // placeholder flag
    };
}
