#include "../pch.h"
#include "../include/AntiSuspend.h"
#include "../include/ThreadRegistry.h"
#include "../include/Logger.h"
#include <windows.h>

namespace OblivionEye {
namespace {
    void ForceResumeAllButSelf(const std::vector<DWORD> &tids) {
        DWORD self = GetCurrentThreadId();
        for (auto tid : tids) {
            if (tid == self)
                continue;
            HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_QUERY_LIMITED_INFORMATION, FALSE, tid);
            if (!hThread)
                continue;
            // Keep resuming until fully running
            for (;;) {
                DWORD prev = ResumeThread(hThread);
                if (prev == static_cast<DWORD>(-1) || prev == 0)
                    break;
            }
            CloseHandle(hThread);
        }
    }
}

AntiSuspend &AntiSuspend::Instance() { static AntiSuspend s; return s; }

void AntiSuspend::Tick() { ForceResumeAllButSelf(GetRegisteredThreadIds()); }
}
