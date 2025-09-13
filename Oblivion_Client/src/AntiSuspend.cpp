#include "../pch.h"
#include "../include/AntiSuspend.h"
#include "../include/ThreadRegistry.h"
#include "../include/Logger.h"
#include <windows.h>

namespace OblivionEye {
    AntiSuspend& AntiSuspend::Instance() { static AntiSuspend s; return s; }

    void AntiSuspend::Tick() {
        auto tids = GetRegisteredThreadIds();
        for (auto tid : tids) {
            if (tid == GetCurrentThreadId()) continue;
            HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_QUERY_LIMITED_INFORMATION, FALSE, tid);
            if (!hThread) continue;
            for (;;) {
                DWORD prev = ResumeThread(hThread);
                if (prev == (DWORD)-1 || prev == 0) break;
            }
            CloseHandle(hThread);
        }
    }
}
