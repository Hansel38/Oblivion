#include "HeartbeatManager.h"
#include <iostream>

void HeartbeatManager::startMonitoring() {
    std::thread([this]() {
        logger.logInfo("Heartbeat monitoring started");

        while (serverRunning) {
            try {
                std::this_thread::sleep_for(heartbeatInterval);

                if (!serverRunning) break;

                std::lock_guard<std::mutex> lock(clientsMutex);
                auto it = activeClients.begin();

                while (it != activeClients.end()) {
                    auto now = std::chrono::steady_clock::now();
                    auto duration = std::chrono::duration_cast<std::chrono::seconds>(
                        now - it->second.lastHeartbeat);

                    if (duration.count() > timeoutDuration.count()) {
                        logger.logWarning("Client timeout: " + it->first +
                            " (Connected for " +
                            std::to_string(it->second.getConnectionDuration().count()) +
                            " seconds)");

                        // Close socket and remove from active clients
                        if (it->second.socket != INVALID_SOCKET_VAL) {
                            closesocket(it->second.socket);
                        }
                        it = activeClients.erase(it);
                    }
                    else {
                        // Hanya kirim ping ke client yang sudah lolos HWID check
                        if (it->second.isAuthenticated) {
                            sendHeartbeatPing(it->second);
                        }
                        else {
                            logger.logDebug("Skipping heartbeat for unauthenticated client: " + it->first);
                        }
                        ++it;
                    }
                }

            }
            catch (const std::exception& e) {
                logger.logError("Exception in heartbeat monitoring: " + std::string(e.what()));
            }
        }

        logger.logInfo("Heartbeat monitoring stopped");
        }).detach();
}

void HeartbeatManager::sendHeartbeatPing(ClientSession& session) {
    std::string pingMessage = "HEARTBEAT_PING";

    int result = send(session.socket, pingMessage.c_str(), pingMessage.length(), 0);
    if (result == -1) {
        logger.logWarning("Failed to send heartbeat ping to " + session.clientKey);
        session.isValid = false;
    }
    else {
        logger.logDebug("Heartbeat ping sent to " + session.clientKey);
    }
}

void HeartbeatManager::handleHeartbeat(const std::string& clientKey) {
    std::lock_guard<std::mutex> lock(clientsMutex);
    auto it = activeClients.find(clientKey);
    if (it != activeClients.end()) {
        it->second.updateHeartbeat();
        logger.logDebug("Heartbeat received from " + clientKey);
    }
}

size_t HeartbeatManager::getConnectedClientsCount() const {
    std::lock_guard<std::mutex> lock(clientsMutex);
    return activeClients.size();
}

ClientSession* HeartbeatManager::getClientSession(const std::string& clientKey) {
    std::lock_guard<std::mutex> lock(clientsMutex);
    auto it = activeClients.find(clientKey);
    if (it != activeClients.end()) {
        return &(it->second);
    }
    return nullptr;
}
