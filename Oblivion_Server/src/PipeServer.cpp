#include <windows.h>
#include <string>
#include <iostream>
#include "../include/PipeServer.h"

int RunPipeServer() {
    const wchar_t* pipeName = L"\\\\.\\pipe\\OblivionEye";
    std::wcout << L"[Server] Starting Named Pipe server at " << pipeName << std::endl;

    HANDLE hPipe = CreateNamedPipeW(
        pipeName,
        PIPE_ACCESS_INBOUND,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        1,
        0,
        4096,
        0,
        nullptr);

    if (hPipe == INVALID_HANDLE_VALUE) {
        std::wcerr << L"[Server] CreateNamedPipe failed.\n";
        return 1;
    }

    std::wcout << L"[Server] Waiting for client...\n";
    BOOL connected = ConnectNamedPipe(hPipe, nullptr) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
    if (!connected) {
        std::wcerr << L"[Server] ConnectNamedPipe failed.\n";
        CloseHandle(hPipe);
        return 1;
    }

    std::wcout << L"[Server] Client connected. Reading...\n";
    char buffer[1024];
    DWORD read = 0;
    while (ReadFile(hPipe, buffer, sizeof(buffer)-1, &read, nullptr)) {
        buffer[read] = '\0';
        std::cout << "[Client] " << buffer << std::endl;
    }

    std::wcout << L"[Server] Client disconnected.\n";
    CloseHandle(hPipe);
    return 0;
}
