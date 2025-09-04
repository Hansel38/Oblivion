#include "../include/Blacklist.h"
#include "../include/Config.h"

// Provide reference so existing extern remains valid but data is in Config
const std::vector<std::string> blacklistedProcesses = Config::Get().blacklistedProcesses;