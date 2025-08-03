#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>
#include <thread>
#include <map>

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

    // Buat socket
    SOCKET serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == INVALID_SOCKET) {
        std::cerr << "Socket creation failed\n";
        WSACleanup();
        return 1;
    }

    // Bind ke port 50001 atau bebas rubah portnya
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

        // Contoh validasi sederhana
        if (request.find("hwid=VALID_HWID_123") != std::string::npos) {
            const char* response = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nALLOW";
            send(clientSocket, response, strlen(response), 0);
        }
        else {
            const char* response = "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nDENY";
            send(clientSocket, response, strlen(response), 0);
        }
    }

    closesocket(clientSocket);
}