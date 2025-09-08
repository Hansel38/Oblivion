#pragma once
#include <string>
#include <atomic>

namespace OblivionEye {
    class PipeCommandClient {
    public:
        static PipeCommandClient& Instance();
        void Start(const std::wstring& pipeName = L"\\\\.\\pipe\\OblivionEyeCmd");
        void Stop();
        bool IsRunning() const { return m_running; }
    private:
        PipeCommandClient() = default;
        void WorkerLoop();
        void HandleCommandLine(const std::string& line);
        void EnsureConnected();
        void ClosePipe();
        std::wstring m_pipeName;
        std::atomic<bool> m_running{ false };
    };
}
