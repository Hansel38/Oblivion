#ifdef _WIN32
#define _WINSOCK_DEPRECATED_NO_WARNINGS
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
// --- TAMBAHKAN INCLUDE UNTUK LOGGER ---
#include "ServerLogger.h"
// ---------------------------------------

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
            // Trim whitespace di awal dan akhir
            line.erase(0, line.find_first_not_of(" \t\r\n"));
            line.erase(line.find_last_not_of(" \t\r\n") + 1);
            // Abaikan baris kosong dan komentar
            if (!line.empty() && line[0] != '#') {
                g_allowedHWIDs.insert(line);
                count++;
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

// Fungsi untuk menangani koneksi dari satu client
void HandleClient(SOCKET ClientSocket, int clientNumber) {
    char recvbuf[DEFAULT_BUFLEN];
    int iResult;
    int recvbuflen = DEFAULT_BUFLEN;

    ServerLogger::Log(S_LOG_CLIENT_CONN, "Client #" + std::to_string(clientNumber) + " connected.");

    // --- TERIMA DATA DARI CLIENT ---
    // Kurangi 1 dari buffer length untuk ruang null-terminator
    iResult = recv(ClientSocket, recvbuf, recvbuflen - 1, 0);
    if (iResult > 0) {
        // Null-terminate buffer dengan aman
        recvbuf[iResult] = '\0';
        std::string receivedData(recvbuf);

        // Log data yang diterima (dibersihkan untuk karakter non-printable)
        std::string cleanData;
        for (char c : receivedData) {
            if (c >= 32 && c <= 126) {
                cleanData += c; // Karakter printable ASCII
            }
            else if (c == '\n') {
                cleanData += "\\n";
            }
            else if (c == '\r') {
                cleanData += "\\r";
            }
            else {
                // Format karakter kontrol/non-ASCII sebagai hex
                char hexBuf[5];
                snprintf(hexBuf, sizeof(hexBuf), "\\x%02X", static_cast<unsigned char>(c));
                cleanData += std::string(hexBuf);
            }
        }
        ServerLogger::Log(S_LOG_CLIENT_DATA, "Client #" + std::to_string(clientNumber) + " sent: " + cleanData);

        // --- PROSES DATA ---
        // Kita tidak melakukan trim di awal karena karakter \n penting untuk parsing.
        // Tapi kita akan membersihkan whitespace dari HWID setelah diekstrak.

        // Cek apakah data dimulai dengan perintah yang dikenali
        if (receivedData.length() >= 14 && receivedData.substr(0, 13) == "VALIDATE_HWID") {
            // Cari karakter ':' setelah "VALIDATE_HWID"
            size_t colonPos = receivedData.find(':', 13);
            if (colonPos != std::string::npos) {
                // Cari karakter newline (\n) setelah ':'
                size_t newlinePos = receivedData.find('\n', colonPos);
                if (newlinePos != std::string::npos) {
                    // Ekstrak HWID dari antara ':' dan '\n'
                    std::string hwid = receivedData.substr(colonPos + 1, newlinePos - colonPos - 1);

                    // Trim whitespace dari HWID
                    hwid.erase(0, hwid.find_first_not_of(" \t\r\n"));
                    hwid.erase(hwid.find_last_not_of(" \t\r\n") + 1);

                    ServerLogger::Log(S_LOG_VALIDATION, "Client #" + std::to_string(clientNumber) + " requesting validation for HWID: " + hwid);

                    // --- VALIDASI HWID ---
                    std::string response;
                    if (g_allowedHWIDs.find(hwid) != g_allowedHWIDs.end()) {
                        response = "VALID\n";
                        ServerLogger::Log(S_LOG_VALIDATION, "Client #" + std::to_string(clientNumber) + " HWID " + hwid + " VALID. Sending approval.");
                    }
                    else {
                        response = "INVALID_HWID\n";
                        ServerLogger::Log(S_LOG_VALIDATION, "Client #" + std::to_string(clientNumber) + " HWID " + hwid + " INVALID. Sending rejection.");
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
                    ServerLogger::Log(S_LOG_WARNING, "Client #" + std::to_string(clientNumber) + " sent malformed request (missing newline). Data: '" + receivedData + "'");
                    send(ClientSocket, "ERROR_MALFORMED\n", 17, 0);
                }
            }
            else {
                ServerLogger::Log(S_LOG_WARNING, "Client #" + std::to_string(clientNumber) + " sent malformed request (missing colon). Data: '" + receivedData + "'");
                send(ClientSocket, "ERROR_MALFORMED\n", 17, 0);
            }
        }
        else {
            ServerLogger::Log(S_LOG_WARNING, "Client #" + std::to_string(clientNumber) + " sent unknown command or invalid format. Data: '" + receivedData + "'");
            send(ClientSocket, "ERROR_UNKNOWN_CMD\n", 19, 0);
        }
    }
    else if (iResult == 0) {
        ServerLogger::Log(S_LOG_CLIENT_CONN, "Client #" + std::to_string(clientNumber) + " closed connection gracefully.");
    }
    else {
        int errorCode = WSAGetLastError();
        ServerLogger::Log(S_LOG_ERROR, "recv failed for client #" + std::to_string(clientNumber) + ". Error: " + std::to_string(errorCode));
        // Jika error adalah WSAECONNRESET, itu berarti client memutus koneksi secara tiba-tiba
        if (errorCode == WSAECONNRESET) {
            ServerLogger::Log(S_LOG_CLIENT_CONN, "Client #" + std::to_string(clientNumber) + " connection was forcibly closed by the remote host.");
        }
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
        int errorCode = WSAGetLastError();
        ServerLogger::Log(S_LOG_ERROR, "Error at socket(): " + std::to_string(errorCode));
        std::cerr << "Error at socket(): " << errorCode << std::endl;
        freeaddrinfo(result);
        WSACleanup();
        ServerLogger::Close();
        return 1;
    }

    // Setup the TCP listening socket
    iResult = bind(ListenSocket, result->ai_addr, (int)result->ai_addrlen);
    if (iResult == SOCKET_ERROR) {
        int errorCode = WSAGetLastError();
        ServerLogger::Log(S_LOG_ERROR, "bind failed with error: " + std::to_string(errorCode));
        std::cerr << "bind failed with error: " << errorCode << std::endl;
        freeaddrinfo(result);
        closesocket(ListenSocket);
        WSACleanup();
        ServerLogger::Close();
        return 1;
    }

    freeaddrinfo(result);

    iResult = listen(ListenSocket, SOMAXCONN);
    if (iResult == SOCKET_ERROR) {
        int errorCode = WSAGetLastError();
        ServerLogger::Log(S_LOG_ERROR, "listen failed with error: " + std::to_string(errorCode));
        std::cerr << "listen failed with error: " << errorCode << std::endl;
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
            // Lanjutkan menunggu client lain meskipun ada error accept
            continue;
        }

        clientCounter++;
        // --- BUAT THREAD BARU UNTUK MENANGANI CLIENT ---
        // Ini memungkinkan server menangani banyak client secara bersamaan
        std::thread clientThread(HandleClient, ClientSocket, clientCounter);
        // Detach thread agar bisa berjalan independen
        clientThread.detach();
    }

    // Cleanup (kode ini tidak akan pernah tercapai dalam loop while(true))
    closesocket(ListenSocket);
    WSACleanup();
    ServerLogger::Close();
    return 0;
}