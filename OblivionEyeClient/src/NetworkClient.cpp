#include "../include/NetworkClient.h"
#include "../include/Logger.h"
#include "../include/HWIDSystem.h" // Untuk generate HWID jika belum ada
#include <windows.h>
#include <wininet.h>
#include <string>

#pragma comment(lib, "wininet.lib")

bool NetworkClient::SendHTTPRequest(const std::string& hwid) {
    Logger::Log("[Network] Initializing WinINet...");
    HINTERNET hInternet = InternetOpenA("OblivionEye/1.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) {
        Logger::Log("[Network] Failed to initialize WinINet");
        return false;
    }

    Logger::Log("[Network] Connecting to server at 127.0.0.1:50001...");
    HINTERNET hConnect = InternetConnectA(
        hInternet,
        "127.0.0.1",       // IP Server
        50001,             // Port Server (disesuaikan)
        NULL, NULL,
        INTERNET_SERVICE_HTTP,
        0, 0
    );

    if (!hConnect) {
        Logger::Log("[Network] Failed to connect to server");
        InternetCloseHandle(hInternet);
        return false;
    }

    Logger::Log("[Network] Opening HTTP request...");
    const char* szAcceptTypes[] = { "text/*", NULL };
    HINTERNET hRequest = HttpOpenRequestA(
        hConnect,
        "POST",
        "/validate",        // Endpoint server
        NULL, NULL, szAcceptTypes,
        0, 0
    );

    if (!hRequest) {
        Logger::Log("[Network] Failed to open HTTP request");
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return false;
    }

    // Data yang dikirim
    std::string postData = "hwid=" + hwid;
    const char* headers = "Content-Type: application/x-www-form-urlencoded";

    Logger::Log("[Network] Sending HTTP request with HWID: " + hwid);
    BOOL bRequestSent = HttpSendRequestA(
        hRequest,
        headers, -1,
        (LPVOID)postData.c_str(), static_cast<DWORD>(postData.length())
    );

    if (!bRequestSent) {
        Logger::Log("[Network] Failed to send HTTP request");
        InternetCloseHandle(hRequest);
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return false;
    }

    // Baca response dari server
    Logger::Log("[Network] Reading server response...");
    char buffer[1024];
    DWORD bytesRead;
    std::string response;
    while (InternetReadFile(hRequest, buffer, sizeof(buffer) - 1, &bytesRead) && bytesRead > 0) {
        buffer[bytesRead] = 0;
        response += buffer;
    }

    Logger::Log("[Network] Server response: " + response);

    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);

    // Cek apakah server mengizinkan
    return (response.find("ALLOW") != std::string::npos);
}

bool NetworkClient::SendHWIDToServer(const std::string& hwid) {
    Logger::Log("[Network] Sending HWID to server: " + hwid);
    return SendHTTPRequest(hwid);
}