#include "../pch.h"
#include "../include/Logger.h"
#include <windows.h>

namespace OblivionEye {
    void Log(const std::wstring& msg) {
        OutputDebugStringW((L"[OblivionEye] " + msg + L"\n").c_str());
    }
}
