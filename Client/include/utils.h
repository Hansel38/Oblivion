#pragma once
#include <Windows.h>
#include <string>

namespace Utils {
    bool IsProcessRunning(const std::wstring& processName);
    void CloseGame();
    void ShowCheatDetectedMessage(const std::wstring& cheatType, const std::wstring& details = L"");
    std::wstring GetProcessName(DWORD processId);
}