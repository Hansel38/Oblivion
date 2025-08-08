#include "ServerLogger.h"
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

// Disable deprecation warnings
#ifdef _MSC_VER
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#endif

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
using Socket = SOCKET;
const Socket INVALID_SOCKET_VAL = INVALID_SOCKET;
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
using Socket = int;
const Socket INVALID_SOCKET_VAL = -1;
#define closesocket close
#endif

class OblivionEyeServer {
private:
    ServerLogger logger;
    Socket serverSocket;
    std::atomic<bool> serverRunning;
    int serverPort;
    std::vector<std::string> allowedHWIDs;
    std::mutex clientMutex;
    std::vector<std::string> connectedClients;

public:
    OblivionEyeServer(int port = 8900)  // Default port 8900
        : serverSocket(INVALID_SOCKET_VAL)
        , serverRunning(false)
        , serverPort(port) {

        // Konfigurasi logger
        LoggerConfig config;
        config.logFilePath = "logs/server.log";
        config.minLogLevel = INFO;
        config.maxFileSizeMB = 10;
        config.maxBackupFiles = 5;
        config.enableConsoleOutput = true;

        logger.configure(config);

        // Load allowed HWIDs
        loadAllowedHWIDs();
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

        // Allow socket reuse
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

        // Start main server loop in separate thread
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
                // Safe way to get client IP
                char clientIP[INET_ADDRSTRLEN];
#ifdef _WIN32
                inet_ntop(AF_INET, &(clientAddr.sin_addr), clientIP, INET_ADDRSTRLEN);
#else
                inet_ntop(AF_INET, &(clientAddr.sin_addr), clientIP, INET_ADDRSTRLEN);
#endif
                int clientPort = ntohs(clientAddr.sin_port);

                logger.logClientConnection(std::string(clientIP), clientPort);

                // Handle client in separate thread
                std::thread clientThread(&OblivionEyeServer::handleClient,
                    this, clientSocket, std::string(clientIP), clientPort);
                clientThread.detach();
            }
            else if (serverRunning) {
                logger.logWarning("Failed to accept client connection");
            }
        }
    }

    void handleClient(Socket clientSocket, const std::string& clientIP, int clientPort) {
        // Add client to connected clients list
        {
            std::lock_guard<std::mutex> lock(clientMutex);
            connectedClients.push_back(clientIP + ":" + std::to_string(clientPort));
        }

        char buffer[4096];
        int bytesReceived;

        try {
            while (serverRunning) {
                bytesReceived = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);

                if (bytesReceived > 0) {
                    buffer[bytesReceived] = '\0';
                    std::string message(buffer);

                    // Remove trailing newline/carriage return
                    message.erase(std::remove(message.begin(), message.end(), '\n'), message.end());
                    message.erase(std::remove(message.begin(), message.end(), '\r'), message.end());

                    processClientMessage(clientSocket, clientIP, message);
                }
                else if (bytesReceived == 0) {
                    // Client disconnected
                    logger.logClientDisconnection(clientIP, clientPort);
                    break;
                }
                else {
                    // Error occurred
                    logger.logWarning("Error receiving data from client " + clientIP);
                    break;
                }
            }
        }
        catch (const std::exception& e) {
            logger.logError("Exception in client handler: " + std::string(e.what()));
        }

        // Remove client from connected clients list
        {
            std::lock_guard<std::mutex> lock(clientMutex);
            auto it = std::find(connectedClients.begin(), connectedClients.end(),
                clientIP + ":" + std::to_string(clientPort));
            if (it != connectedClients.end()) {
                connectedClients.erase(it);
            }
        }

        closesocket(clientSocket);
    }

    void processClientMessage(Socket clientSocket, const std::string& clientIP,
        const std::string& message) {
        logger.logDebug("Received message from " + clientIP + ": " + message);

        // Parse message by splitting on colon
        size_t colonPos = message.find(':');
        std::string command, data;

        if (colonPos != std::string::npos) {
            command = message.substr(0, colonPos);
            data = message.substr(colonPos + 1);
        }
        else {
            command = message;
            data = "";
        }

        // Handle different commands
        if (command == "HWID_CHECK" || command == "VALIDATE_HWID") {
            handleHWIDCheck(clientSocket, clientIP, data);
        }
        else if (command == "SECURITY_REPORT") {
            handleSecurityReport(clientIP, data);
        }
        else if (command == "STATUS_UPDATE") {
            handleStatusUpdate(clientIP, data);
        }
        else {
            logger.logWarning("Unknown command from " + clientIP + ": " + command);
            sendResponse(clientSocket, "ERROR:Unknown command");
        }
    }

    void handleHWIDCheck(Socket clientSocket, const std::string& clientIP,
        const std::string& hwid) {
        // Trim whitespace dari HWID
        std::string cleanHWID = hwid;
        cleanHWID.erase(0, cleanHWID.find_first_not_of(" \t\r\n"));
        cleanHWID.erase(cleanHWID.find_last_not_of(" \t\r\n") + 1);

        bool allowed = isHWIDAllowed(cleanHWID);

        // Logging dengan format yang lebih spesifik
        if (allowed) {
            logger.logClientHWIDCheck(clientIP, cleanHWID, true);
            sendResponse(clientSocket, "VALIDATION_SUCCESS");
        }
        else {
            logger.logClientHWIDCheck(clientIP, cleanHWID, false);
            sendResponse(clientSocket, "VALIDATION_FAILED");

            logger.logSecurity("Unauthorized HWID attempt from " + clientIP +
                " with HWID: " + cleanHWID);
        }
    }

    void handleSecurityReport(const std::string& clientIP, const std::string& report) {
        logger.logClientSecurityAlert(clientIP, "CLIENT_REPORT", report);
        // Here you could save the report to database or take other actions
    }

    void handleStatusUpdate(const std::string& clientIP, const std::string& status) {
        logger.logInfo("Status update from " + clientIP + ": " + status);
        // Process status update
    }

    bool isHWIDAllowed(const std::string& hwid) {
        // Trim whitespace for comparison
        std::string cleanHWID = hwid;
        cleanHWID.erase(0, cleanHWID.find_first_not_of(" \t\r\n"));
        cleanHWID.erase(cleanHWID.find_last_not_of(" \t\r\n") + 1);

        return std::find(allowedHWIDs.begin(), allowedHWIDs.end(), cleanHWID) != allowedHWIDs.end();
    }

    void loadAllowedHWIDs() {
        allowedHWIDs.clear();
        std::ifstream file("allowed_hwids.txt");

        if (!file.is_open()) {
            logger.logWarning("Could not open allowed_hwids.txt, no HWIDs loaded");
            return;
        }

        std::string line;
        while (std::getline(file, line)) {
            // Remove whitespace and empty lines
            line.erase(0, line.find_first_not_of(" \t\r\n"));
            line.erase(line.find_last_not_of(" \t\r\n") + 1);

            if (!line.empty()) {
                allowedHWIDs.push_back(line);
            }
        }

        file.close();
        logger.logInfo("Loaded " + std::to_string(allowedHWIDs.size()) + " allowed HWIDs");
    }

    void sendResponse(Socket clientSocket, const std::string& response) {
        // Kirim response tanpa karakter tambahan
        std::string cleanResponse = response;
        // Clean any potential whitespace
        cleanResponse.erase(0, cleanResponse.find_first_not_of(" \t\r\n"));
        cleanResponse.erase(cleanResponse.find_last_not_of(" \t\r\n") + 1);

        logger.logDebug("Sending response: '" + cleanResponse + "'");
        send(clientSocket, cleanResponse.c_str(), cleanResponse.length(), 0);
    }

    void stop() {
        if (serverRunning) {
            logger.logInfo("Stopping OblivionEye Server...");
            serverRunning = false;

            if (serverSocket != INVALID_SOCKET_VAL) {
                closesocket(serverSocket);
                serverSocket = INVALID_SOCKET_VAL;
            }

#ifdef _WIN32
            WSACleanup();
#endif

            logger.logInfo("Server stopped");
        }
    }

    void showStatus() {
        std::lock_guard<std::mutex> lock(clientMutex);
        logger.logInfo("=== Server Status ===");
        logger.logInfo("Connected clients: " + std::to_string(connectedClients.size()));

        for (const auto& client : connectedClients) {
            logger.logInfo("  - " + client);
        }

        logger.logInfo("Allowed HWIDs: " + std::to_string(allowedHWIDs.size()));
        logger.logInfo("====================");
    }

    ServerLogger& getLogger() {
        return logger;
    }
};

// Global server instance
OblivionEyeServer* g_server = nullptr;
std::atomic<bool> g_running(true);

// Signal handler for graceful shutdown
void signalHandler(int signal) {
    std::cout << "\nReceived signal " << signal << ", shutting down..." << std::endl;
    g_running = false;
    if (g_server) {
        g_server->stop();
    }
}

void showHelp() {
    std::cout << "OblivionEye Server Commands:" << std::endl;
    std::cout << "  help     - Show this help" << std::endl;
    std::cout << "  status   - Show server status" << std::endl;
    std::cout << "  reload   - Reload allowed HWIDs" << std::endl;
    std::cout << "  quit     - Shutdown server" << std::endl;
    std::cout << "  exit     - Shutdown server" << std::endl;
}

int main(int argc, char* argv[]) {
    std::cout << "==================================" << std::endl;
    std::cout << "  OblivionEye Anti-Cheat Server   " << std::endl;
    std::cout << "==================================" << std::endl;

    int port = 8900;  // Default port 8900
    if (argc > 1) {
        port = std::atoi(argv[1]);
        if (port <= 0 || port > 65535) {
            std::cerr << "Invalid port number. Using default port 8900." << std::endl;
            port = 8900;
        }
    }

    // Setup signal handlers
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
#ifdef _WIN32
    signal(SIGBREAK, signalHandler);
#endif

    // Create and start server
    OblivionEyeServer server(port);
    g_server = &server;

    if (!server.start()) {
        std::cerr << "Failed to start server!" << std::endl;
        return 1;
    }

    std::cout << "Server started on port " << port << ". Type 'help' for commands." << std::endl;

    // Command loop
    std::string command;
    while (g_running) {
        std::cout << "> ";
        if (std::getline(std::cin, command)) {
            // Trim whitespace
            command.erase(0, command.find_first_not_of(" \t\r\n"));
            command.erase(command.find_last_not_of(" \t\r\n") + 1);

            if (command == "help") {
                showHelp();
            }
            else if (command == "status") {
                server.showStatus();
            }
            else if (command == "reload") {
                server.loadAllowedHWIDs();
                server.getLogger().logInfo("HWID list reloaded");
            }
            else if (command == "quit" || command == "exit") {
                g_running = false;
                break;
            }
            else if (!command.empty()) {
                std::cout << "Unknown command: " << command << std::endl;
                std::cout << "Type 'help' for available commands." << std::endl;
            }
        }
        else {
            // EOF or error
            break;
        }

        // Small delay to prevent busy waiting
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    server.stop();
    std::cout << "Server shutdown complete." << std::endl;

    return 0;
}