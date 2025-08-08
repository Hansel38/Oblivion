#ifndef HEARTBEAT_MANAGER_H
#define HEARTBEAT_MANAGER_H

#include "ClientSession.h"
#include "ServerLogger.h"
#include <map>
#include <mutex>
#include <thread>
#include <atomic>
#include <chrono>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <sys/socket.h>
#define closesocket close
#endif

class HeartbeatManager {
private:
    std::map<std::string, ClientSession>& activeClients;
    std::mutex& clientsMutex;
    ServerLogger& logger;
    std::atomic<bool>& serverRunning;
    std::chrono::seconds heartbeatInterval;
    std::chrono::seconds timeoutDuration;

public:
    HeartbeatManager(std::map<std::string, ClientSession>& clients,
        std::mutex& mutex,
        ServerLogger& serverLogger,
        std::atomic<bool>& running,
        std::chrono::seconds interval = std::chrono::seconds(30),
        std::chrono::seconds timeout = std::chrono::seconds(90))
        : activeClients(clients), clientsMutex(mutex), logger(serverLogger),
        serverRunning(running), heartbeatInterval(interval), timeoutDuration(timeout) {
    }

    // Start heartbeat monitoring thread
    void startMonitoring();

    // Handle heartbeat from client
    void handleHeartbeat(const std::string& clientKey);

    // Send heartbeat ping to client
    void sendHeartbeatPing(ClientSession& session);

    // Get connected clients count
    size_t getConnectedClientsCount() const;

    // Get client session by key
    ClientSession* getClientSession(const std::string& clientKey);
};

#endif // HEARTBEAT_MANAGER_H