// SelfCheck.h - Internal runtime self-verification (not a public API)
#pragma once
#include <string>

namespace OblivionEye {
    // Runs a lightweight internal self-check when enabled via environment variable.
    // Returns aggregated status string (may be logged) or empty on fatal abort.
    std::wstring RunInternalSelfCheck();
}
