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
#include "../include/Config.h"
#include "../include/StringUtil.h"
#include "../include/SharedKey.h"
#include "../include/HashUtil.h"
#include <wincrypt.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

namespace OblivionEye {

    static HANDLE g_hPipe = INVALID_HANDLE_VALUE;
    static bool   g_authenticated = false; // set true after handshake success
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
        // Sequence number (monotonic) appended into plain segment BEFORE HMAC so HMAC covers it.
        uint64_t seq = m_seqCounter.fetch_add(1, std::memory_order_relaxed);
        std::ostringstream base;
        base << payloadUtf8 << "|SEQ=" << seq; // Always add SEQ (even if HMAC disabled) for future diagnostics
        std::string plain = base.str();
        // HMAC opsional atas payload plain (pre-CRC, pre-XOR): H = SHA256(key + plain)
        if (m_hmacEnabled) {
            auto key = SharedKeyManager::Instance().GetUtf8();
            auto hmac = HashUtil::Sha256HexLower(key + plain);
            if (!hmac.empty()) plain += std::string("|H=") + hmac;
        }
        uint32_t nonce = m_nonceCounter.fetch_add(1, std::memory_order_relaxed);
        std::string withCrc = AppendCrcIfEnabled(plain);
        std::string transformed = m_rollingXor ? ApplyRollingXor(withCrc, m_xorKey, nonce) : withCrc;
        std::ostringstream oss;
        oss << "NONCE=" << std::hex << std::setw(8) << std::setfill('0') << nonce << ";" << transformed;
        return oss.str();
    }

    void PipeClient::Send(const std::wstring& msg) {
        auto utf8 = StringUtil::WideToUtf8(msg);
        if (utf8.empty()) return;
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

    // HashUtil dipakai untuk SHA-256 (lihat HashUtil.h)

    void PipeClient::EnsureConnected() {
        if (g_hPipe != INVALID_HANDLE_VALUE && g_authenticated) return;
        if (g_hPipe == INVALID_HANDLE_VALUE) {
            g_hPipe = CreateFileW(m_pipeName.c_str(), GENERIC_WRITE | GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (g_hPipe == INVALID_HANDLE_VALUE) return; // retry nanti
            Log(L"PipeClient connected (handshake pending)");
            g_authenticated = false;
        }
        if (!g_authenticated) {
            // Prepare client nonce & send HELLO
            unsigned long long nonceCli = 0;
            if(BCryptGenRandom(nullptr,(PUCHAR)&nonceCli,sizeof(nonceCli),BCRYPT_USE_SYSTEM_PREFERRED_RNG)!=0) {
                nonceCli = GetTickCount64() ^ (uintptr_t)this; // fallback
            }
            std::ostringstream hello; hello << "HELLO " << std::hex << nonceCli << "\n";
            DWORD written=0; WriteFile(g_hPipe, hello.str().c_str(), (DWORD)hello.str().size(), &written, nullptr);
            // Read CHALLENGE line
            std::string line; char ch; DWORD read=0; BOOL okB;
            DWORD start = GetTickCount();
            while(GetTickCount() - start < Config::PIPE_HANDSHAKE_TIMEOUT_MS) {
                okB = ReadFile(g_hPipe,&ch,1,&read,nullptr);
                if(!okB || read==0){ std::this_thread::sleep_for(std::chrono::milliseconds(10)); continue; }
                if(ch=='\n') break; else line.push_back(ch);
            }
            if(line.rfind("CHALLENGE ",0)!=0){ ClosePipe(); return; }
            std::string nonceSrvHex = line.substr(10);
            std::ostringstream nc; nc<<std::hex<<nonceCli; std::string nonceCliHex = nc.str();
            std::string keyUtf8 = SharedKeyManager::Instance().GetUtf8();
            std::string digest = HashUtil::Sha256HexLower(keyUtf8 + nonceCliHex + nonceSrvHex);
            std::string authLine = std::string("AUTH ") + digest + "\n";
            WriteFile(g_hPipe, authLine.c_str(), (DWORD)authLine.size(), &written, nullptr);
            // Await OK/FAIL
            line.clear(); start = GetTickCount();
            while(GetTickCount() - start < Config::PIPE_HANDSHAKE_TIMEOUT_MS) {
                okB = ReadFile(g_hPipe,&ch,1,&read,nullptr);
                if(!okB || read==0){ std::this_thread::sleep_for(std::chrono::milliseconds(10)); continue; }
                if(ch=='\n') break; else line.push_back(ch);
            }
            if(line == "OK" || line == "OK HMAC") {
                g_authenticated = true;
                if(line == "OK HMAC") {
                    // Auto-enable HMAC if server mandates it
                    m_hmacEnabled = true;
                    Log(L"PipeClient handshake OK (HMAC enforced)");
                } else {
                    Log(L"PipeClient handshake OK");
                }
            }
            else { ClosePipe(); }
        }
    }

    void PipeClient::WorkerLoop() {
        Log(L"PipeClient start");
        while (m_running) {
            EnsureConnected();
            if (g_hPipe == INVALID_HANDLE_VALUE || !g_authenticated) { std::this_thread::sleep_for(std::chrono::milliseconds(Config::PIPE_RECONNECT_MS)); continue; }
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
                std::this_thread::sleep_for(std::chrono::milliseconds(Config::PIPE_IDLE_SLEEP_MS));
            }
        }
        ClosePipe();
        Log(L"PipeClient stop");
    }
}
