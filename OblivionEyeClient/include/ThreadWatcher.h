#ifndef THREAD_WATCHER_H
#define THREAD_WATCHER_H

#include <windows.h>
#include <vector>
#include <string>

namespace OblivionEye {

    class ThreadWatcher {
    public:
        // Memeriksa apakah ada thread yang mencurigakan
        static bool ScanForSuspiciousThreads();

    private:
        // Fungsi pembantu untuk membandingkan nama module
        static bool IsModuleInBlacklist(const std::wstring& moduleName);
    };

} // namespace OblivionEye

#endif // THREAD_WATCHER_H