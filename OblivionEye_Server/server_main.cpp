#include "ServerLogger.h"
#include "ClientSession.h"
#include "HeartbeatManager.h"
#include "EncryptionHandler.h"
#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include <fstream>
#include <algorithm>
#include <atomic>
#include <csignal>
#include <chrono>
#include <cstring>
#include <map>
#include <memory>

#ifdef _MSC_VER
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#endif

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
using Socket = SOCKET;
#define INVALID_SOCKET_VAL INVALID_SOCKET
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
using Socket = int;
#define INVALID_SOCKET_VAL -1
#define closesocket close
#endif

class OblivionEyeServer {
private:
    ServerLogger logger;
    Socket serverSocket;
    std::atomic<bool> serverRunning;
    int serverPort;
    std::vector<std::string> allowedHWIDs;

    std::map<std::string, ClientSession> activeClients;
    std::mutex clientsMutex;
    std::unique_ptr<HeartbeatManager> heartbeatManager;
    std::unique_ptr<EncryptionHandler> encryptionHandler;

    bool devMode; // <=== mode development

public:
    OblivionEyeServer(int port = 8900, bool dev = false)
        : serverSocket(INVALID_SOCKET_VAL),
        serverRunning(false),
        serverPort(port),
        devMode(dev)
    {
        LoggerConfig config;
        config.logFilePath = "logs/server.log";
        config.minLogLevel = LOG_INFO;
        config.maxFileSizeMB = 10;
        config.maxBackupFiles = 5;
        config.enableConsoleOutput = true;
        logger.configure(config);

        loadAllowedHWIDs();

        encryptionHandler = std::make_unique<EncryptionHandler>("OblivionEye_Secret_2025");
        logger.logInfo("DEBUG: Encryption initialized with key length: " +
            std::to_string(std::string("OblivionEye_Secret_2025").length()));

        if (devMode) {
            logger.logWarning("!!! SERVER RUNNING IN DEVELOPMENT MODE (AUTO-ADD HWID ENABLED) !!!");
        }
    }

    ~OblivionEyeServer() {
        stop();
    }

    bool initialize() {
#ifdef _WIN32
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            logger.logError("Failed to initialize Winsock");
            return false;
        }
#endif
        return true;
    }

    bool start() {
        logger.logInfo("Initializing OblivionEye Server...");

        if (!initialize()) {
            return false;
        }

        serverSocket = socket(AF_INET, SOCK_STREAM, 0);
        if (serverSocket == INVALID_SOCKET_VAL) {
            logger.logError("Failed to create server socket");
            return false;
        }

        int opt = 1;
#ifdef _WIN32
        setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR,
            (const char*)&opt, sizeof(opt));
#else
        setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR,
            &opt, sizeof(opt));
#endif

        sockaddr_in serverAddr;
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_addr.s_addr = INADDR_ANY;
        serverAddr.sin_port = htons(serverPort);

        if (bind(serverSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == -1) {
            logger.logError("Failed to bind socket to port " + std::to_string(serverPort));
            return false;
        }

        if (listen(serverSocket, 10) == -1) {
            logger.logError("Failed to listen on socket");
            return false;
        }

        serverRunning = true;
        logger.logInfo("OblivionEye Server started on port " + std::to_string(serverPort));
        logger.logInfo("Allowed HWIDs loaded: " + std::to_string(allowedHWIDs.size()));
        logger.logInfo("Encryption: " + std::string(encryptionHandler->isEncryptionEnabled() ? "ENABLED" : "DISABLED"));

        heartbeatManager = std::make_unique<HeartbeatManager>(
            activeClients, clientsMutex, logger, serverRunning,
            std::chrono::seconds(30), std::chrono::seconds(90));
        heartbeatManager->startMonitoring();

        std::thread serverThread(&OblivionEyeServer::serverLoop, this);
        serverThread.detach();

        return true;
    }

    void serverLoop() {
        logger.logInfo("Server main loop started");

        while (serverRunning) {
            sockaddr_in clientAddr;
            socklen_t clientAddrLen = sizeof(clientAddr);

            Socket clientSocket = accept(serverSocket,
                (struct sockaddr*)&clientAddr,
                &clientAddrLen);

            if (clientSocket != INVALID_SOCKET_VAL) {
                char clientIP[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &(clientAddr.sin_addr), clientIP, INET_ADDRSTRLEN);
                int clientPort = ntohs(clientAddr.sin_port);

                logger.logClientConnection(std::string(clientIP), clientPort);

                std::thread clientThread(&OblivionEyeServer::handleClient,
                    this, clientSocket, std::string(clientIP), clientPort);
                clientThread.detach();
            }
        }
    }

    void handleClient(Socket clientSocket, const std::string& clientIP, int clientPort) {
        std::string clientKey = clientIP + ":" + std::to_string(clientPort);

        {
            std::lock_guard<std::mutex> lock(clientsMutex);
            activeClients.emplace(clientKey, ClientSession(clientSocket, clientIP, clientPort));
        }

        char buffer[4096];
        int bytesReceived;

        while (serverRunning) {
            bytesReceived = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
            if (bytesReceived > 0) {
                buffer[bytesReceived] = '\0';
                std::string decryptedMessage = encryptionHandler->decryptMessage(buffer);
                processClientMessage(clientSocket, clientIP, clientPort, decryptedMessage);
            }
            else {
                logger.logClientDisconnection(clientIP, clientPort);
                break;
            }
        }

        {
            std::lock_guard<std::mutex> lock(clientsMutex);
            activeClients.erase(clientKey);
        }

        closesocket(clientSocket);
    }

    void processClientMessage(Socket clientSocket, const std::string& clientIP, int clientPort,
        const std::string& message)
    {
        std::string clientKey = clientIP + ":" + std::to_string(clientPort);
        {
            std::lock_guard<std::mutex> lock(clientsMutex);
            auto it = activeClients.find(clientKey);
            if (it != activeClients.end()) {
                it->second.updateHeartbeat();
            }
        }

        if (message.rfind("VALIDATE_HWID:", 0) == 0) {
            handleHWIDCheck(clientSocket, clientIP, clientPort, message.substr(14));
        }
    }

    void handleHWIDCheck(Socket clientSocket, const std::string& clientIP, int clientPort,
        const std::string& hwid)
    {
        std::string cleanHWID = hwid;
        cleanHWID.erase(0, cleanHWID.find_first_not_of(" \t\r\n"));
        cleanHWID.erase(cleanHWID.find_last_not_of(" \t\r\n") + 1);

        bool allowed = isHWIDAllowed(cleanHWID);

        if (allowed) {
            logger.logClientHWIDCheck(clientIP, cleanHWID, true);
            sendResponse(clientSocket, "VALIDATION_SUCCESS");
        }
        else {
            logger.logClientHWIDCheck(clientIP, cleanHWID, false);

            if (devMode) {
                logger.logInfo("DEV MODE: Auto-adding HWID " + cleanHWID);
                allowedHWIDs.push_back(cleanHWID);
                std::ofstream file("allowed_hwids.txt", std::ios::app);
                if (file.is_open()) {
                    file << cleanHWID << "\n";
                }
                sendResponse(clientSocket, "VALIDATION_SUCCESS");
            }
            else {
                sendResponse(clientSocket, "VALIDATION_FAILED");
                logger.logSecurity("Unauthorized HWID attempt from " + clientIP + " with HWID: " + cleanHWID);
            }
        }
    }

    bool isHWIDAllowed(const std::string& hwid) {
        return std::find(allowedHWIDs.begin(), allowedHWIDs.end(), hwid) != allowedHWIDs.end();
    }

    void loadAllowedHWIDs() {
        allowedHWIDs.clear();
        std::ifstream file("allowed_hwids.txt");
        std::string line;
        while (std::getline(file, line)) {
            line.erase(0, line.find_first_not_of(" \t\r\n"));
            line.erase(line.find_last_not_of(" \t\r\n") + 1);
            if (!line.empty()) allowedHWIDs.push_back(line);
        }
        logger.logInfo("Loaded " + std::to_string(allowedHWIDs.size()) + " allowed HWIDs");
    }

    void sendResponse(Socket clientSocket, const std::string& response) {
        std::string encryptedResponse = encryptionHandler->encryptMessage(response);
        send(clientSocket, encryptedResponse.c_str(), encryptedResponse.length(), 0);
    }

    void stop() {
        if (serverRunning) {
            logger.logInfo("Stopping server...");
            serverRunning = false;
            if (serverSocket != INVALID_SOCKET_VAL) {
                closesocket(serverSocket);
            }
#ifdef _WIN32
            WSACleanup();
#endif
        }
    }
};

OblivionEyeServer* g_server = nullptr;
std::atomic<bool> g_running(true);

void signalHandler(int signal) {
    g_running = false;
    if (g_server) g_server->stop();
}

int main(int argc, char* argv[]) {
    bool devMode = false;
    int port = 8900;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--dev") devMode = true;
        else port = std::atoi(arg.c_str());
    }

    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);

    OblivionEyeServer server(port, devMode);
    g_server = &server;

    if (!server.start()) {
        std::cerr << "Failed to start server!\n";
        return 1;
    }

    while (g_running) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    server.stop();
    return 0;
}
