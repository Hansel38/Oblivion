#include "../pch.h"
#include "../include/AntiSuspend.h"
#include "../include/ThreadRegistry.h"
#include "../include/Logger.h"
#include <windows.h>
#include <thread>
#include <chrono>

namespace OblivionEye {
    AntiSuspend& AntiSuspend::Instance() { static AntiSuspend s; return s; }

    void AntiSuspend::Start(unsigned intervalMs) {
        if (m_running.exchange(true)) return;
        std::thread([this, intervalMs]() { Loop(intervalMs); }).detach();
    }

    void AntiSuspend::Stop() { m_running = false; }

    void AntiSuspend::Loop(unsigned intervalMs) {
        Log(L"AntiSuspend start");
        while (m_running) {
            auto tids = GetRegisteredThreadIds();
            for (auto tid : tids) {
                if (tid == GetCurrentThreadId()) continue; // skip self
                HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_QUERY_LIMITED_INFORMATION, FALSE, tid);
                if (!hThread) continue;
                // Coba resume jika ada suspend count
                for (;;) {
                    DWORD prev = ResumeThread(hThread);
                    if (prev == (DWORD)-1 || prev == 0) break; // error atau sudah 0
                }
                CloseHandle(hThread);
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(intervalMs));
        }
        Log(L"AntiSuspend stop");
    }
}
