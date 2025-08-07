#include "../include/ServerCommunication.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>
#include "../include/Logger.h"

#pragma comment(lib, "ws2_32.lib")

bool PerformServerValidation(const std::string& hwid) {
    Logger::Log(LOG_INFO, "Attempting to contact validation server...");

    // Inisialisasi Winsock
    WSADATA wsaData;
    int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        Logger::Log(LOG_ERROR, "WSAStartup failed: " + std::to_string(iResult));
        // Dalam skenario keamanan, gagal inisialisasi sering dianggap sebagai potensi ancaman.
        // Namun, untuk kemudahan pengembangan, kita bisa memilih untuk melanjutkan.
        // Untuk produksi, pertimbangkan untuk return false.
        return false; // Untuk demo, kita anggap gagal.
    }

    // Buat socket
    SOCKET ConnectSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (ConnectSocket == INVALID_SOCKET) {
        Logger::Log(LOG_ERROR, "Socket creation failed: " + std::to_string(WSAGetLastError()));
        WSACleanup();
        return false;
    }

    // Alamat server
    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(12345); // Port server (bisa dibuat konfigurable)
    // Alamat IP server (bisa dibuat konfigurable)
    // Untuk produksi, jangan hardcode. Gunakan enkripsi atau unduh dari sumber aman.
    inet_pton(AF_INET, "127.0.0.1", &serverAddr.sin_addr);

    // Koneksi ke server (dengan timeout implisit dari OS)
    iResult = connect(ConnectSocket, (SOCKADDR*)&serverAddr, sizeof(serverAddr));
    if (iResult == SOCKET_ERROR) {
        int err = WSAGetLastError();
        Logger::Log(LOG_ERROR, "Failed to connect to server (Error: " + std::to_string(err) + ").");
        closesocket(ConnectSocket);
        WSACleanup();
        // Tidak bisa koneksi. Tergantung kebijakan: lanjut atau hentikan.
        // Untuk demo, kita bisa pilih untuk melanjutkan jika server tidak wajib.
        // Namun, karena ini adalah "Server-Side Validation", gagal koneksi sering berarti gagal validasi.
        return false; // Untuk konsistensi dengan nama fungsi, return false.
    }

    Logger::Log(LOG_INFO, "Connected to validation server.");

    // Format dan kirim data
    // Protokol sederhana: "VALIDATE_HWID:<hwid>\n"
    std::string dataToSend = "VALIDATE_HWID:" + hwid + "\n";
    iResult = send(ConnectSocket, dataToSend.c_str(), (int)dataToSend.length(), 0);
    if (iResult == SOCKET_ERROR) {
        Logger::Log(LOG_ERROR, "Failed to send data to server: " + std::to_string(WSAGetLastError()));
        closesocket(ConnectSocket);
        WSACleanup();
        return false;
    }
    Logger::Log(LOG_INFO, "Sent validation request to server.");

    // Terima respons (blocking recv, tanpa timeout khusus untuk demo)
    char recvBuffer[512];
    iResult = recv(ConnectSocket, recvBuffer, 511, 0);
    if (iResult > 0) {
        recvBuffer[iResult] = '\0'; // Null-terminate
        std::string response(recvBuffer);
        Logger::Log(LOG_INFO, "Received response from server: " + response);

        // Tutup koneksi
        closesocket(ConnectSocket);
        WSACleanup();

        // Periksa respons. Misalnya, server kirim "VALID" jika OK.
        if (response.find("VALID") != std::string::npos) {
            Logger::Log(LOG_INFO, "Server validation successful.");
            return true;
        }
        else {
            Logger::Log(LOG_DETECTED, "Server validation failed. Response: " + response);
            return false;
        }
    }
    else if (iResult == 0) {
        Logger::Log(LOG_ERROR, "Server closed connection unexpectedly.");
    }
    else {
        Logger::Log(LOG_ERROR, "Failed to receive data from server: " + std::to_string(WSAGetLastError()));
    }

    // Tutup koneksi jika ada error
    closesocket(ConnectSocket);
    WSACleanup();
    return false; // Gagal menerima respons valid
}