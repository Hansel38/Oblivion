#pragma once

class AntiDebug {
public:
    static bool IsDebuggerDetected();
private:
    static bool CheckIsDebuggerPresent();
    static bool CheckRemoteDebugger();
    static bool CheckHardwareBreakpoints();
    static bool CheckTiming();
    static bool CheckNtQueryInfo();
    static bool CheckOutputDebugString();
    static bool CheckInt3();
    static bool CheckSEH();
};