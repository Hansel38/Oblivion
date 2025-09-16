#pragma once
#include <string>
#include <atomic>

namespace OblivionEye {
    // Abstraksi transport telemetry agar mudah menambahkan TLS nanti.
    class ITelemetryTransport {
    public:
        virtual ~ITelemetryTransport() = default;
        virtual bool Start(const std::wstring& host, unsigned short port) = 0; // non-blocking prefer
        virtual void Stop() = 0;
        virtual void Send(const std::string& line) = 0; // harus newline-ready (pemanggil tambahkan \n)
        virtual bool IsRunning() const = 0;
        virtual bool IsTls() const = 0;
    };
}
