#pragma once
#include <string>
#include <atomic>

namespace OblivionEye {
    class PipeClient {
    public:
        static PipeClient& Instance();
        void Start(const std::wstring& pipeName = L"\\\\.\\pipe\\OblivionEye");
        void Stop();
        void Send(const std::wstring& msg);
        void Send(const std::string& msg);
        bool IsRunning() const { return m_running; }
    private:
        PipeClient() = default;
        void WorkerLoop();
        void EnsureConnected();
        void ClosePipe();
        std::wstring m_pipeName;
        void Enqueue(const std::string& msg);
        std::atomic<bool> m_running{ false };
    };
}
