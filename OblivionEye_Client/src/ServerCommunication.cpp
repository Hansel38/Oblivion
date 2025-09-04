#include "../include/ServerCommunication.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>
#include <thread>
#include <atomic>
#include "../include/Logger.h"
#include "../include/EncryptionHandler.h"
#include "../include/Config.h"

#pragma comment(lib, "ws2_32.lib")

// State global sederhana (bisa nanti dibungkus class)
static SOCKET g_ServerSocket = INVALID_SOCKET;
static std::atomic<bool> g_Running{ false };
static std::thread g_RecvThread; // thread listener
static EncryptionHandler g_EncHandler; // gunakan key dari Config

static void CloseSocketSafe() {
    if (g_ServerSocket != INVALID_SOCKET) {
        closesocket(g_ServerSocket);
        g_ServerSocket = INVALID_SOCKET;
    }
}

bool IsServerSessionAlive() { return g_Running.load(); }

static void RecvLoop() {
    Logger::Log(LOG_INFO, "Server session listener started");

    char buf[1024];
    while (g_Running.load()) {
        int n = recv(g_ServerSocket, buf, (int)sizeof(buf) - 1, 0);
        if (n > 0) {
            buf[n] = '\0';
            std::string raw(buf);
            std::string msg = g_EncHandler.decryptMessage(raw);

            // Bisa jadi server mengirim beberapa frame sekaligus (belum ada framing). Untuk sederhana, proses line per line
            size_t start = 0; 
            while (start < msg.size()) {
                size_t pos = msg.find('\n', start);
                std::string line = msg.substr(start, pos == std::string::npos ? std::string::npos : pos - start);
                if (pos == std::string::npos) start = msg.size(); else start = pos + 1;
                if (line.empty()) continue;

                if (line == "HEARTBEAT_PING") {
                    std::string pong = g_EncHandler.encryptMessage("HEARTBEAT_PONG");
                    send(g_ServerSocket, pong.c_str(), (int)pong.size(), 0);
                    Logger::Log(LOG_INFO, "Heartbeat pong sent");
                }
                else if (line == "VALIDATION_SUCCESS") {
                    // ignore
                }
                else if (line == "VALIDATION_FAILED") {
                    Logger::Log(LOG_DETECTED, "Server reported validation failed after initial success?");
                }
                else {
                    Logger::Log(LOG_INFO, std::string("Unknown server message: ") + line);
                }
            }
        }
        else if (n == 0) {
            Logger::Log(LOG_WARNING, "Server closed connection");
            break;
        }
        else {
            int err = WSAGetLastError();
            if (err == WSAEWOULDBLOCK || err == WSAETIMEDOUT) {
                // non fatal
                continue;
            }
            Logger::Log(LOG_ERROR, "Recv error from server: " + std::to_string(err));
            break;
        }
    }

    g_Running = false;
    CloseSocketSafe();
    WSACleanup();
    Logger::Log(LOG_INFO, "Server session listener stopped");
}

bool PerformServerValidation(const std::string& hwid) {
    if (g_Running.load()) {
        Logger::Log(LOG_INFO, "Validation already active");
        return true;
    }

    Logger::Log(LOG_INFO, "Attempting to contact validation server...");

    WSADATA wsaData; int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        Logger::Log(LOG_ERROR, "WSAStartup failed: " + std::to_string(iResult));
        return false;
    }

    g_ServerSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (g_ServerSocket == INVALID_SOCKET) {
        Logger::Log(LOG_ERROR, "Socket creation failed: " + std::to_string(WSAGetLastError()));
        WSACleanup();
        return false;
    }

    int timeoutMs = 5000; // 5s initial operations
    setsockopt(g_ServerSocket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeoutMs, sizeof(timeoutMs));

    sockaddr_in serverAddr{}; serverAddr.sin_family = AF_INET; serverAddr.sin_port = htons(8900);
    inet_pton(AF_INET, "127.0.0.1", &serverAddr.sin_addr);

    iResult = connect(g_ServerSocket, (SOCKADDR*)&serverAddr, sizeof(serverAddr));
    if (iResult == SOCKET_ERROR) {
        int err = WSAGetLastError();
        Logger::Log(LOG_ERROR, "Failed to connect to server (Error: " + std::to_string(err) + ")");
        CloseSocketSafe();
        WSACleanup();
        return false;
    }

    Logger::Log(LOG_INFO, "Connected to validation server.");

    std::string payload = "VALIDATE_HWID:" + hwid; // tanpa newline
    std::string toSend = g_EncHandler.encryptMessage(payload);
    iResult = send(g_ServerSocket, toSend.c_str(), (int)toSend.size(), 0);
    if (iResult == SOCKET_ERROR) {
        Logger::Log(LOG_ERROR, "Failed to send validation data: " + std::to_string(WSAGetLastError()));
        CloseSocketSafe();
        WSACleanup();
        return false;
    }

    char buf[512];
    iResult = recv(g_ServerSocket, buf, 511, 0);
    if (iResult <= 0) {
        if (iResult == 0) Logger::Log(LOG_ERROR, "Server closed before validation response");
        else Logger::Log(LOG_ERROR, "Failed to receive validation response: " + std::to_string(WSAGetLastError()));
        CloseSocketSafe();
        WSACleanup();
        return false;
    }

    buf[iResult] = '\0';
    std::string respDecrypted = g_EncHandler.decryptMessage(std::string(buf));
    Logger::Log(LOG_INFO, "Validation server response: " + respDecrypted);

    if (respDecrypted.find("VALIDATION_SUCCESS") == std::string::npos) {
        Logger::Log(LOG_DETECTED, "Validation failed");
        CloseSocketSafe();
        WSACleanup();
        return false;
    }

    timeoutMs = 10000; // 10 detik loop listener
    setsockopt(g_ServerSocket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeoutMs, sizeof(timeoutMs));

    g_Running = true;
    g_RecvThread = std::thread(RecvLoop);
    Logger::Log(LOG_INFO, "Server-side validation established (persistent session)");
    return true;
}

void ShutdownServerSession() {
    if (!g_Running.load()) return;
    Logger::Log(LOG_INFO, "Shutting down server session...");
    g_Running = false;
    CloseSocketSafe();
    if (g_RecvThread.joinable()) g_RecvThread.join();
    WSACleanup();
}