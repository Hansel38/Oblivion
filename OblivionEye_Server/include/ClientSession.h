#ifndef CLIENT_SESSION_H
#define CLIENT_SESSION_H

#include <string>
#include <chrono>

#ifdef _WIN32
#include <winsock2.h>
using Socket = SOCKET;
const Socket INVALID_SOCKET_VAL = INVALID_SOCKET;
#else
#include <sys/socket.h>
using Socket = int;
const Socket INVALID_SOCKET_VAL = -1;
#endif

class ClientSession {
public:
    Socket socket;
    std::string ip;
    int port;
    std::string clientKey;
    std::chrono::steady_clock::time_point lastHeartbeat;
    std::chrono::steady_clock::time_point connectedTime;
    bool isValid;
    bool isAuthenticated;

    ClientSession(Socket s, const std::string& clientIP, int clientPort)
        : socket(s), ip(clientIP), port(clientPort),
        clientKey(clientIP + ":" + std::to_string(clientPort)),
        lastHeartbeat(std::chrono::steady_clock::now()),
        connectedTime(std::chrono::steady_clock::now()),
        isValid(true), isAuthenticated(false) {
    }

    // Update heartbeat timestamp
    void updateHeartbeat() {
        lastHeartbeat = std::chrono::steady_clock::now();
    }

    // Check if client is still alive (within 90 seconds)
    bool isAlive() const {
        auto now = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(
            now - lastHeartbeat);
        return duration.count() <= 90;
    }

    // Get connection duration
    std::chrono::seconds getConnectionDuration() const {
        auto now = std::chrono::steady_clock::now();
        return std::chrono::duration_cast<std::chrono::seconds>(
            now - connectedTime);
    }
};

#endif // CLIENT_SESSION_H