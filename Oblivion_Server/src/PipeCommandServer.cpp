#include <windows.h>
#include <string>
#include <iostream>
#include "../include/PipeCommandServer.h"

int RunPipeCommandServer() {
    const wchar_t* pipeName = L"\\\\.\\pipe\\OblivionEyeCmd";
    std::wcout << L"[CmdServer] Starting Named Pipe command server at " << pipeName << std::endl;

    HANDLE hPipe = CreateNamedPipeW(
        pipeName,
        PIPE_ACCESS_OUTBOUND,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        1,
        4096,
        0,
        0,
        nullptr);

    if (hPipe == INVALID_HANDLE_VALUE) {
        std::wcerr << L"[CmdServer] CreateNamedPipe failed.\n";
        return 1;
    }

    std::wcout << L"[CmdServer] Waiting for client...\n";
    BOOL connected = ConnectNamedPipe(hPipe, nullptr) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
    if (!connected) {
        std::wcerr << L"[CmdServer] ConnectNamedPipe failed.\n";
        CloseHandle(hPipe);
        return 1;
    }

    std::wcout << L"[CmdServer] Client connected. Commands: CLOSE_CLIENT, UPDATE_BLACKLIST <process.exe>, UPDATE_MODULE_BLACKLIST <dllname>, UPDATE_OVERLAY_BLACKLIST_TITLE <title contains...>, UPDATE_OVERLAY_BLACKLIST_CLASS <class contains...>, UPDATE_DRIVER_BLACKLIST <driver.sys>, REQUEST_HEARTBEAT_NOW, exit\n";
    for (;;) {
        std::string line;
        std::getline(std::cin, line);
        if (line.empty()) continue;
        line.push_back('\n'); // newline agar parser client membaca satu perintah per baris
        DWORD written = 0;
        BOOL ok = WriteFile(hPipe, line.c_str(), (DWORD)line.size(), &written, nullptr);
        if (!ok) break;
        if (line == "exit\n") break;
    }
    CloseHandle(hPipe);
    return 0;
}
