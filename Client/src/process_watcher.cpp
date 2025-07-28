#include "../include/process_watcher.h"
#include "../include/blacklist.h"
#include "../include/utils.h"
#include <vector>

namespace ProcessWatcher {
    bool CheckBlacklistedProcesses() {
        for (const auto& process : BLACKLISTED_PROCESSES) {
            if (Utils::IsProcessRunning(process)) {
                // Tampilkan pesan jika diperlukan untuk debugging
                // MessageBoxW(nullptr, (L"Cheat detected: " + process).c_str(), L"Oblivion Eye", MB_ICONERROR);
                return true; // Cheat terdeteksi
            }
        }
        return false;
    }
}