#pragma once
#include <string>
#include <atomic>
#include <cstdint>

namespace OblivionEye {
    class PipeClient {
    public:
        static PipeClient& Instance();
        void Start(const std::wstring& pipeName = L"\\\\.\\pipe\\OblivionEye");
        void Stop();
        void Send(const std::wstring& msg);
        void Send(const std::string& msg);
        bool IsRunning() const { return m_running; }
        void SetXorKey(uint8_t k) { m_xorKey = k; }
        void SetCrcEnabled(bool e) { m_crcEnabled = e; }
        void SetRollingXorEnabled(bool e) { m_rollingXor = e; }
        void RotateXorKey(uint8_t newKey, bool resetNonce = true) { m_xorKey = newKey; if (resetNonce) m_nonceCounter = 1; }
    private:
        PipeClient() = default;
        void WorkerLoop();
        void EnsureConnected();
        void ClosePipe();
        void Enqueue(const std::string& msg);
        std::string AppendCrcIfEnabled(const std::string& plain);
        uint32_t CalcCrc32(const uint8_t* data, size_t len);
        std::string BuildPacket(const std::string& payloadUtf8); // adds CRC + rolling xor + header
        std::string ApplyRollingXor(const std::string& in, uint8_t baseKey, uint32_t nonce);
        std::wstring m_pipeName;
        std::atomic<bool> m_running{ false };
        uint8_t m_xorKey = 0; // base key
        bool m_crcEnabled = false;
        bool m_rollingXor = false;
        std::atomic<uint32_t> m_nonceCounter{ 1 };
    };
}
