#ifdef _WIN32
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define NOMINMAX  // Prevent Windows.h from defining min/max macros
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <thread>
#include <vector>
#include <string>
#include <sstream>
#include <fstream>
#include <set>
#include <algorithm>
#include <cctype>
#include <iomanip>
#include "ServerLogger.h"

#pragma comment(lib, "ws2_32.lib")

#define DEFAULT_PORT "12345"
#define DEFAULT_BUFLEN 512
#define HWID_LIST_FILE "allowed_hwids.txt"

// --- SIMPAN DAFTAR HWID YANG DIIZINKAN ---
static std::set<std::string> g_allowedHWIDs;
// ------------------------------------------

// --- FUNGSI UNTUK MEMUAT DAFTAR HWID DARI FILE ---
bool LoadAllowedHWIDsFromFile(const std::string& filename) {
    std::ifstream file(filename);
    std::string line;
    if (file.is_open()) {
        g_allowedHWIDs.clear();
        int count = 0;
        while (std::getline(file, line)) {
            // Remove whitespace and newlines
            line.erase(0, line.find_first_not_of(" \t\r\n"));
            line.erase(line.find_last_not_of(" \t\r\n") + 1);
            if (!line.empty() && line[0] != '#') {
                g_allowedHWIDs.insert(line);
                count++;
                ServerLogger::Log(S_LOG_INFO, "Added HWID to whitelist: " + line);
            }
        }
        file.close();
        ServerLogger::Log(S_LOG_INFO, "Successfully loaded " + std::to_string(count) + " allowed HWIDs from " + filename);
        return true;
    }
    else {
        ServerLogger::Log(S_LOG_ERROR, "Could not open " + filename + ". Please make sure the file exists.");
        return false;
    }
}
// ----------------------------------------------

// Function to convert string to hex for debugging
std::string StringToHex(const std::string& str) {
    std::stringstream ss;
    for (unsigned char c : str) {
        ss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(c) << " ";
    }
    return ss.str();
}

// Fungsi untuk menangani koneksi dari satu client
void HandleClient(SOCKET ClientSocket, int clientNumber) {
    char recvbuf[DEFAULT_BUFLEN];
    int iResult;
    int recvbuflen = DEFAULT_BUFLEN;

    ServerLogger::Log(S_LOG_CLIENT_CONN, "Client #" + std::to_string(clientNumber) + " connected.");

    // --- TERIMA DATA DARI CLIENT ---
    iResult = recv(ClientSocket, recvbuf, recvbuflen - 1, 0);
    if (iResult > 0) {
        recvbuf[iResult] = '\0'; // Null-terminate dengan aman
        std::string receivedData(recvbuf);

        // Enhanced logging with hex dump
        std::string cleanData;
        for (char c : receivedData) {
            if (c >= 32 && c <= 126) cleanData += c;
            else if (c == '\n') cleanData += "\\n";
            else if (c == '\r') cleanData += "\\r";
            else cleanData += "\\x" + std::to_string(static_cast<unsigned char>(c));
        }

        ServerLogger::Log(S_LOG_CLIENT_DATA, "Client #" + std::to_string(clientNumber) + " sent (" + std::to_string(iResult) + " bytes): " + cleanData);
        ServerLogger::Log(S_LOG_CLIENT_DATA, "Hex dump: " + StringToHex(receivedData));

        // --- IMPROVED DATA PROCESSING ---
        // Check if data starts with VALIDATE_HWID:
        std::string expectedPrefix = "VALIDATE_HWID:";

        ServerLogger::Log(S_LOG_CLIENT_DATA, "Checking prefix. Expected: '" + expectedPrefix + "', Received first " + std::to_string(expectedPrefix.length()) + " chars: '" + receivedData.substr(0, expectedPrefix.length()) + "'");

        if (receivedData.length() >= expectedPrefix.length() &&
            receivedData.substr(0, expectedPrefix.length()) == expectedPrefix) {

            // Find the end of HWID (could be \n, \r\n, or end of string)
            size_t hwidStart = expectedPrefix.length();
            size_t hwidEnd = receivedData.find_first_of("\r\n", hwidStart);
            if (hwidEnd == std::string::npos) {
                hwidEnd = receivedData.length();
            }

            std::string hwid = receivedData.substr(hwidStart, hwidEnd - hwidStart);

            // Trim whitespace from HWID
            hwid.erase(0, hwid.find_first_not_of(" \t"));
            hwid.erase(hwid.find_last_not_of(" \t") + 1);

            ServerLogger::Log(S_LOG_VALIDATION, "Client #" + std::to_string(clientNumber) + " requesting validation for HWID: '" + hwid + "' (length: " + std::to_string(hwid.length()) + ")");

            // --- VALIDASI HWID ---
            std::string response;
            bool isValid = false;

            // Check if HWID exists in allowed list
            if (!hwid.empty() && g_allowedHWIDs.find(hwid) != g_allowedHWIDs.end()) {
                response = "VALID\n";
                isValid = true;
                ServerLogger::Log(S_LOG_VALIDATION, "Client #" + std::to_string(clientNumber) + " HWID '" + hwid + "' is VALID. Sending approval.");
            }
            else {
                response = "INVALID_HWID\n";
                ServerLogger::Log(S_LOG_VALIDATION, "Client #" + std::to_string(clientNumber) + " HWID '" + hwid + "' is INVALID. Sending rejection.");

                // Log all allowed HWIDs for debugging
                ServerLogger::Log(S_LOG_VALIDATION, "Current allowed HWIDs count: " + std::to_string(g_allowedHWIDs.size()));
                int debugCount = 0;
                for (const auto& allowedHwid : g_allowedHWIDs) {
                    ServerLogger::Log(S_LOG_VALIDATION, "Allowed HWID #" + std::to_string(++debugCount) + ": '" + allowedHwid + "' (length: " + std::to_string(allowedHwid.length()) + ")");
                    if (debugCount >= 5) { // Limit debug output
                        ServerLogger::Log(S_LOG_VALIDATION, "... and " + std::to_string(g_allowedHWIDs.size() - debugCount) + " more");
                        break;
                    }
                }
            }

            // --- KIRIM RESPON ---
            iResult = send(ClientSocket, response.c_str(), (int)response.length(), 0);
            if (iResult == SOCKET_ERROR) {
                ServerLogger::Log(S_LOG_ERROR, "Failed to send response to client #" + std::to_string(clientNumber) + ". Error: " + std::to_string(WSAGetLastError()));
            }
            else {
                ServerLogger::Log(S_LOG_CLIENT_DATA, "Sent response to client #" + std::to_string(clientNumber) + ": " + response.substr(0, response.length() - 1));
            }
        }
        else {
            // Enhanced error reporting
            ServerLogger::Log(S_LOG_WARNING, "Client #" + std::to_string(clientNumber) + " sent unknown command.");
            ServerLogger::Log(S_LOG_WARNING, "Expected prefix: '" + expectedPrefix + "'");
            ServerLogger::Log(S_LOG_WARNING, "Received data length: " + std::to_string(receivedData.length()));
            if (receivedData.length() > 0) {
                size_t prefixLen = (receivedData.length() < expectedPrefix.length()) ? receivedData.length() : expectedPrefix.length();
                std::string actualPrefix = receivedData.substr(0, prefixLen);
                ServerLogger::Log(S_LOG_WARNING, "Actual prefix: '" + actualPrefix + "'");
            }

            std::string errorResponse = "ERROR_UNKNOWN_CMD\n";
            send(ClientSocket, errorResponse.c_str(), (int)errorResponse.length(), 0);
        }
    }
    else if (iResult == 0) {
        ServerLogger::Log(S_LOG_CLIENT_CONN, "Client #" + std::to_string(clientNumber) + " closed connection gracefully.");
    }
    else {
        ServerLogger::Log(S_LOG_ERROR, "recv failed for client #" + std::to_string(clientNumber) + ". Error: " + std::to_string(WSAGetLastError()));
    }

    // --- TUTUP KONEKSI ---
    closesocket(ClientSocket);
    ServerLogger::Log(S_LOG_CLIENT_CONN, "Client #" + std::to_string(clientNumber) + " connection closed.");
}

int main() {
    // Inisialisasi Logger Server
    ServerLogger::Initialize("server.log");

    WSADATA wsaData;
    int iResult;

    ServerLogger::Log(S_LOG_INFO, "Starting Oblivion Eye Validation Server...");

    // Inisialisasi Winsock
    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        ServerLogger::Log(S_LOG_ERROR, "WSAStartup failed: " + std::to_string(iResult));
        std::cerr << "WSAStartup failed: " << iResult << std::endl;
        ServerLogger::Close();
        return 1;
    }

    // --- MUAT DAFTAR HWID DARI FILE ---
    if (!LoadAllowedHWIDsFromFile(HWID_LIST_FILE)) {
        ServerLogger::Log(S_LOG_ERROR, "Server cannot start without a valid HWID list. Exiting.");
        std::cerr << "Server cannot start without a valid HWID list. Exiting." << std::endl;
        WSACleanup();
        ServerLogger::Close();
        return 1;
    }
    // ----------------------------------

    struct addrinfo* result = NULL;
    struct addrinfo hints;

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    // Resolve the server address and port
    iResult = getaddrinfo(NULL, DEFAULT_PORT, &hints, &result);
    if (iResult != 0) {
        ServerLogger::Log(S_LOG_ERROR, "getaddrinfo failed: " + std::to_string(iResult));
        std::cerr << "getaddrinfo failed: " << iResult << std::endl;
        WSACleanup();
        ServerLogger::Close();
        return 1;
    }

    // Create a SOCKET for connecting to server
    SOCKET ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (ListenSocket == INVALID_SOCKET) {
        ServerLogger::Log(S_LOG_ERROR, "Error at socket(): " + std::to_string(WSAGetLastError()));
        std::cerr << "Error at socket(): " << WSAGetLastError() << std::endl;
        freeaddrinfo(result);
        WSACleanup();
        ServerLogger::Close();
        return 1;
    }

    // Setup the TCP listening socket
    iResult = bind(ListenSocket, result->ai_addr, (int)result->ai_addrlen);
    if (iResult == SOCKET_ERROR) {
        ServerLogger::Log(S_LOG_ERROR, "bind failed with error: " + std::to_string(WSAGetLastError()));
        std::cerr << "bind failed with error: " << WSAGetLastError() << std::endl;
        freeaddrinfo(result);
        closesocket(ListenSocket);
        WSACleanup();
        ServerLogger::Close();
        return 1;
    }

    freeaddrinfo(result);

    iResult = listen(ListenSocket, SOMAXCONN);
    if (iResult == SOCKET_ERROR) {
        ServerLogger::Log(S_LOG_ERROR, "listen failed with error: " + std::to_string(WSAGetLastError()));
        std::cerr << "listen failed with error: " << WSAGetLastError() << std::endl;
        closesocket(ListenSocket);
        WSACleanup();
        ServerLogger::Close();
        return 1;
    }

    ServerLogger::Log(S_LOG_INFO, "Oblivion Eye Validation Server is running on port " + std::string(DEFAULT_PORT));
    ServerLogger::Log(S_LOG_INFO, "Using HWID list from: " + std::string(HWID_LIST_FILE));
    std::cout << "========================================" << std::endl;
    std::cout << "Oblivion Eye Validation Server is running on port " << DEFAULT_PORT << std::endl;
    std::cout << "Using HWID list from: " << HWID_LIST_FILE << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Waiting for client connections..." << std::endl;
    std::cout << "(Check logs/server.log for detailed logs)" << std::endl;

    // --- LOOP UTAMA SERVER ---
    int clientCounter = 0;
    while (true) {
        // Accept a client socket
        SOCKET ClientSocket = accept(ListenSocket, NULL, NULL);
        if (ClientSocket == INVALID_SOCKET) {
            int err = WSAGetLastError();
            ServerLogger::Log(S_LOG_ERROR, "accept failed: " + std::to_string(err));
            std::cerr << "accept failed: " << err << std::endl;
            continue;
        }

        clientCounter++;
        // --- BUAT THREAD BARU UNTUK MENANGANI CLIENT ---
        std::thread clientThread(HandleClient, ClientSocket, clientCounter);
        clientThread.detach();
    }

    // Cleanup
    closesocket(ListenSocket);
    WSACleanup();
    ServerLogger::Close();
    return 0;
}