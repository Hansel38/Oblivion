#include "../pch.h"
#include "../include/PipeClient.h"
#include "../include/Logger.h"
#include <windows.h>
#include <thread>
#include <mutex>
#include <queue>
#include <string>
#include <sstream>
#include <iomanip>

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

    uint32_t PipeClient::CalcCrc32(const uint8_t* data, size_t len) {
        uint32_t crc = 0xFFFFFFFFu;
        for (size_t i = 0; i < len; ++i) {
            crc ^= data[i];
            for (int b = 0; b < 8; ++b) {
                uint32_t bit = crc & 1u;
                crc >>= 1;
                if (bit) crc ^= 0xEDB88320u;
            }
        }
        return ~crc;
    }

    std::string PipeClient::AppendCrcIfEnabled(const std::string& plain) {
        if (!m_crcEnabled) return plain;
        uint32_t crc = CalcCrc32(reinterpret_cast<const uint8_t*>(plain.data()), plain.size());
        char suffix[16];
        sprintf_s(suffix, "|CRC=%08X", crc);
        return plain + suffix;
    }

    std::string PipeClient::ApplyRollingXor(const std::string& in, uint8_t baseKey, uint32_t nonce) {
        if (baseKey == 0) return in; // disabled
        std::string out = in;
        // Simple rolling: key_i = baseKey ^ ( (nonce >> (i % 24)) & 0xFF ) ^ (i * 31)
        for (size_t i = 0; i < out.size(); ++i) {
            uint8_t dynamicPart = static_cast<uint8_t>((nonce >> (i % 24)) & 0xFF);
            uint8_t k = static_cast<uint8_t>(baseKey ^ dynamicPart ^ (uint8_t)(i * 31));
            out[i] = static_cast<char>(out[i] ^ k);
        }
        return out;
    }

    std::string PipeClient::BuildPacket(const std::string& payloadUtf8) {
        // Layout (ascii): NONCE=xxxxxxxx;DATA=<obf bytes>
        uint32_t nonce = m_nonceCounter.fetch_add(1, std::memory_order_relaxed);
        std::string msg = AppendCrcIfEnabled(payloadUtf8);
        std::string obf = m_rollingXor ? ApplyRollingXor(msg, m_xorKey, nonce) : msg;
        std::ostringstream oss;
        oss << "NONCE=" << std::hex << std::setw(8) << std::setfill('0') << nonce << ";" << obf;
        return oss.str();
    }

    void PipeClient::Send(const std::wstring& msg) {
        int len = WideCharToMultiByte(CP_UTF8, 0, msg.c_str(), -1, nullptr, 0, nullptr, nullptr);
        std::string utf8(len, '\0');
        WideCharToMultiByte(CP_UTF8, 0, msg.c_str(), -1, &utf8[0], len, nullptr, nullptr);
        if (!utf8.empty() && utf8.back()=='\0') utf8.pop_back();
        Enqueue(BuildPacket(utf8));
    }

    void PipeClient::Send(const std::string& msg) {
        Enqueue(BuildPacket(msg));
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
            // retry nanti
        } else {
            Log(L"PipeClient connected");
        }
    }

    void PipeClient::WorkerLoop() {
        Log(L"PipeClient start");
        while (m_running) {
            EnsureConnected();
            if (g_hPipe == INVALID_HANDLE_VALUE) { std::this_thread::sleep_for(std::chrono::milliseconds(2000)); continue; }
            std::string msg;
            {
                std::lock_guard<std::mutex> lk(g_qMtx);
                if (!g_queue.empty()) { msg = g_queue.front(); g_queue.pop(); }
            }
            if (!msg.empty()) {
                DWORD written = 0;
                BOOL ok = WriteFile(g_hPipe, msg.c_str(), (DWORD)msg.size(), &written, nullptr);
                if (!ok) ClosePipe();
            } else {
                std::this_thread::sleep_for(std::chrono::milliseconds(200));
            }
        }
        ClosePipe();
        Log(L"PipeClient stop");
    }
}
