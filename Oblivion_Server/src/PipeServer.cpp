#include <windows.h>
#include <string>
#include <iostream>
#include <vector>
#include <cstdint>
#include <sstream>
#include <iomanip>
#include "../include/PipeServer.h"

static uint32_t CalcCrc32(const uint8_t* data, size_t len) {
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; ++i) {
        crc ^= data[i];
        for (int b = 0; b < 8; ++b) {
            uint32_t bit = crc & 1u; crc >>= 1; if (bit) crc ^= 0xEDB88320u;
        }
    }
    return ~crc;
}

static bool VerifyAndStripCrc(std::string& msg) {
    size_t pos = msg.rfind("|CRC="); if (pos == std::string::npos) return true; std::string body = msg.substr(0,pos); std::string crcPart = msg.substr(pos+5); if (crcPart.size()!=8) return false; uint32_t claimed=0; std::stringstream ss; ss<<std::hex<<crcPart; ss>>claimed; uint32_t calc = CalcCrc32(reinterpret_cast<const uint8_t*>(body.data()), body.size()); if (calc!=claimed) return false; msg=body; return true;
}

static std::string ApplyRollingXor(const std::string& in, uint8_t baseKey, uint32_t nonce) {
    if (baseKey == 0) return in;
    std::string out = in;
    for (size_t i = 0; i < out.size(); ++i) {
        uint8_t dynamicPart = static_cast<uint8_t>((nonce >> (i % 24)) & 0xFF);
        uint8_t k = static_cast<uint8_t>(baseKey ^ dynamicPart ^ (uint8_t)(i * 31));
        out[i] = static_cast<char>(out[i] ^ k);
    }
    return out;
}

int RunPipeServer() {
    const wchar_t* pipeName = L"\\\\.\\pipe\\OblivionEye";
    std::wcout << L"[Server] Starting Named Pipe server at " << pipeName << std::endl;

    HANDLE hPipe = CreateNamedPipeW(pipeName, PIPE_ACCESS_INBOUND, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, 1, 0, 4096, 0, nullptr);
    if (hPipe == INVALID_HANDLE_VALUE) { std::wcerr << L"[Server] CreateNamedPipe failed.\n"; return 1; }

    std::wcout << L"[Server] Waiting for client...\n";
    BOOL connected = ConnectNamedPipe(hPipe, nullptr) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
    if (!connected) { std::wcerr << L"[Server] ConnectNamedPipe failed.\n"; CloseHandle(hPipe); return 1; }

    uint8_t baseKey = 0; // samakan dengan client (SetXorKey) bila ingin aktif
    bool rolling = true; // set true jika client SetRollingXorEnabled(true)
    bool expectCrc = false; // set true jika client juga mengirim CRC

    std::wcout << L"[Server] Client connected. Reading... (baseKey=" << (int)baseKey << L", rolling=" << (rolling?L"ON":L"OFF") << L", CRC=" << (expectCrc?L"ON":L"OFF") << L")\n";

    char buffer[2048]; DWORD read = 0;
    while (ReadFile(hPipe, buffer, sizeof(buffer)-1, &read, nullptr)) {
        buffer[read] = '\0'; std::string packet(buffer, read);
        // Packet format: NONCE=xxxxxxxx;....data....
        uint32_t nonce = 0; bool parsedNonce=false;
        if (packet.rfind("NONCE=",0)==0) {
            if (packet.size() > 15 && packet[14]==';') { // NONCE= + 8 hex + ';' -> pos 14
                std::string hexNonce = packet.substr(6,8); std::stringstream ss; ss<<std::hex<<hexNonce; ss>>nonce; parsedNonce=true; packet.erase(0,15);
            }
        }
        std::string payload = packet;
        if (rolling && parsedNonce) payload = ApplyRollingXor(payload, baseKey, nonce);
        bool crcOk = true; if (expectCrc) crcOk = VerifyAndStripCrc(payload); else VerifyAndStripCrc(payload);
        std::cout << (crcOk?"[Client] ":"[Client][CRCFAIL] ") << payload << std::endl;
    }

    std::wcout << L"[Server] Client disconnected.\n";
    CloseHandle(hPipe); return 0;
}
