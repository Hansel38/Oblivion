#pragma once
#include <Windows.h>
#include <string>

// Forward declaration untuk namespace lain
namespace AntiDebug { bool IsDebugged(); }
namespace ProcessWatcher { bool CheckBlacklistedProcesses(); }
namespace OverlayScanner { bool DetectOverlayWindows(); }
namespace AntiSuspend { bool IsThreadSuspended(); }
namespace InjectionScanner { bool DetectInjectedModules(); }
namespace MemoryScanner { bool ScanMemoryForSignatures(); }

namespace Utils {
    bool IsProcessRunning(const std::wstring& processName);
    void CloseGame();
    void ShowCheatDetectedMessage(const std::wstring& cheatType);
    std::wstring GetProcessName(DWORD processId);
}