// OblivionEye.Server/server.cpp
#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>
#include <thread>
#include <unordered_map>
#include "Whitelist.h" //  Tambahkan ini

#pragma comment(lib, "ws2_32.lib")

// Forward declaration
void HandleClient(SOCKET clientSocket);

int main() {
    // Inisialisasi Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed\n";
        return 1;
    }

    // Load whitelist HWID
    HWIDWhitelist::LoadWhitelist();

    // Buat socket
    SOCKET serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == INVALID_SOCKET) {
        std::cerr << "Socket creation failed\n";
        WSACleanup();
        return 1;
    }

    // Bind ke port 50001
    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(50001);
    serverAddr.sin_addr.s_addr = INADDR_ANY;

    if (bind(serverSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "Bind failed\n";
        closesocket(serverSocket);
        WSACleanup();
        return 1;
    }

    // Listen
    if (listen(serverSocket, SOMAXCONN) == SOCKET_ERROR) {
        std::cerr << "Listen failed\n";
        closesocket(serverSocket);
        WSACleanup();
        return 1;
    }

    std::cout << "OblivionEye Server listening on port 50001...\n";

    // Accept client
    while (true) {
        SOCKET clientSocket = accept(serverSocket, NULL, NULL);
        if (clientSocket != INVALID_SOCKET) {
            std::cout << "Client connected\n";
            std::thread(HandleClient, clientSocket).detach();
        }
    }

    closesocket(serverSocket);
    WSACleanup();
    return 0;
}

// Handle client request
void HandleClient(SOCKET clientSocket) {
    char buffer[1024] = { 0 };
    int bytesReceived = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);

    if (bytesReceived > 0) {
        std::string request(buffer);
        std::cout << "Request: " << request << "\n";

        // Ekstrak HWID dari request
        std::string hwid;
        size_t pos = request.find("hwid=");
        if (pos != std::string::npos) {
            hwid = request.substr(pos + 5);
            // Bersihkan jika ada & lainnya
            size_t ampPos = hwid.find('&');
            if (ampPos != std::string::npos) {
                hwid = hwid.substr(0, ampPos);
            }
            std::cout << "Received HWID: " << hwid << "\n";
        }

        // Validasi HWID
        if (!hwid.empty() && HWIDWhitelist::IsHWIDAllowed(hwid)) {
            const char* response = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nALLOW";
            send(clientSocket, response, strlen(response), 0);
            std::cout << "HWID " << hwid << " ALLOWED\n";
        }
        else {
            const char* response = "HTTP/1.1 403 Forbidden\r\nContent-Length: 4\r\n\r\nDENY";
            send(clientSocket, response, strlen(response), 0);
            std::cout << "HWID " << hwid << " DENIED\n";
        }
    }

    closesocket(clientSocket);
}