#pragma once
#include <vector>
#include <windows.h>

namespace OblivionEye {
    void RegisterThreadId(DWORD tid);
    void UnregisterThreadId(DWORD tid);
    std::vector<DWORD> GetRegisteredThreadIds();
}
