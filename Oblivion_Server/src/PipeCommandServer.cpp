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
    if (!connected) { std::wcerr << L"[CmdServer] ConnectNamedPipe failed.\n"; CloseHandle(hPipe); return 1; }

    std::wcout << L"[CmdServer] Client connected. Commands:\n"
                 L"  CLOSE_CLIENT\n"
                 L"  UPDATE_BLACKLIST <process.exe>\n"
                 L"  UPDATE_MODULE_BLACKLIST <dllname>\n"
                 L"  UPDATE_OVERLAY_BLACKLIST_TITLE <title>\n"
                 L"  UPDATE_OVERLAY_BLACKLIST_CLASS <class>\n"
                 L"  UPDATE_DRIVER_BLACKLIST <driver.sys>\n"
                 L"  WHITELIST_PUBLISHER_ADD <CN>\n"
                 L"  WHITELIST_FILE_ADD <full_path>\n"
                 L"  KILL_PROCESS <pid>\n"
                 L"  QUARANTINE_FILE <full_path>\n"
                 L"  REQUEST_HEARTBEAT_NOW\n"
                 L"  PROLOG_ADD_TARGET <module> <func> [bytes]\n"
                 L"  PROLOG_REBASELINE\n"
                 L"  PROLOG_LIST\n"
                 L"  PIPE_SET_XOR_KEY <hex_byte>\n"
                 L"  PIPE_SET_CRC_ON | PIPE_SET_CRC_OFF\n"
                 L"  PIPE_ROLLING_XOR_ON | PIPE_ROLLING_XOR_OFF\n"
                 L"  HEARTBEAT_ADAPTIVE_ON | HEARTBEAT_ADAPTIVE_OFF\n"
                 L"  POLICY_LOAD <full_path_to_policy>\n"
                 L"  POLICY_SAVE <full_path_to_policy>\n"
                 L"  WHITELIST_CHUNK_ADD <module> <chunkIndex>\n"
                 L"  GET_STATUS\n"
                 L"  exit\n";

    for (;;) {
        std::string line; std::getline(std::cin, line); if (line.empty()) continue; line.push_back('\n');
        DWORD written = 0; BOOL ok = WriteFile(hPipe, line.c_str(), (DWORD)line.size(), &written, nullptr); if (!ok) break; if (line == "exit\n") break;
    }
    CloseHandle(hPipe); return 0;
}
