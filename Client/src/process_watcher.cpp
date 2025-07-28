#include "../include/process_watcher.h"
#include "../include/blacklist.h"
#include "../include/utils.h"
#include <vector>

namespace ProcessWatcher {
    bool CheckBlacklistedProcesses() {
        for (const auto& process : BLACKLISTED_PROCESSES) {
            if (Utils::IsProcessRunning(process)) {
                return true; // Cheat terdeteksi
            }
        }
        return false;
    }
}