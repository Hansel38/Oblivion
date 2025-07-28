#pragma once

#include <Windows.h>

namespace AntiDebug {
    bool IsDebugged();
    bool CheckDebuggerPresent();
    bool CheckNtQuerySystemInformation();
    bool CheckDebugRegisters();
    bool CheckRegistryForDebuggers();
    bool IsSecuritySoftwareDebugger();
}