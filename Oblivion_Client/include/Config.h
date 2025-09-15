#pragma once
// Central configuration constants for OblivionEye anti-cheat client.
// Adjust here instead of editing scattered magic numbers.

#include <cstddef>
#include <cstdint>

namespace OblivionEye::Config {

// Pipe / command rate limiting
constexpr unsigned CMD_WINDOW_MS            = 3000;   // Time window for command spam control
constexpr unsigned CMD_MAX_RECENT           = 20;     // Max commands inside window
constexpr unsigned CMD_RISK_COOLDOWN_MS     = 2000;   // Cooldown for risky commands (kill, quarantine)
constexpr unsigned CMD_ABUSE_THRESHOLD      = 5;      // After this many cooldown violations we go silent

// Scheduler adaptive tuning
constexpr double   ADAPT_INCREASE_THRESHOLD = 75.0;   // ms average to increase interval
constexpr double   ADAPT_DECREASE_THRESHOLD = 25.0;   // ms average to decrease interval
constexpr unsigned ADAPT_INTERVAL_MULT_MAX  = 4;      // Max multiple of base interval
constexpr unsigned SCHED_MIN_SLEEP_MS       = 10;     // Minimum scheduler loop sleep clamp
constexpr unsigned DEFAULT_SLOW_ALERT_STREAK= 3;      // Default consecutive slow detections
constexpr double   DEFAULT_SLOW_THRESHOLD_MS= 120.0;  // Default slow detector threshold

// Process watcher polling fallback
constexpr unsigned PROC_WATCH_POLL_IDLE_MS  = 1200;   // Sleep when no growth
constexpr unsigned PROC_WATCH_POLL_ACTIVE_MS= 750;    // Sleep when list changed

// Pipe reconnect + idle
constexpr unsigned PIPE_RECONNECT_MS        = 2000;
constexpr unsigned PIPE_IDLE_SLEEP_MS       = 200;    // Sleep when no queued message

// TCP client idle
constexpr unsigned TCP_IDLE_SLEEP_MS        = 200;    // Socket send idle sleep

// Integrity / hashing constants (cryptographic constants remain inline where standard)
// (e.g., SHA-256 K constants left in-place for clarity.)

// Buffer / size limits
constexpr size_t PIPE_CMD_BUFFER        = 1024;              // Command pipe read buffer size
constexpr size_t PIPE_READ_BUFFER       = 1024;              // Generic pipe read buffer (future use)
constexpr size_t TCP_HOST_MAX           = 256;               // Max hostname bytes (UTF-8 incl null)
constexpr size_t MODULE_ENUM_MAX        = 1024;              // Max modules array for EnumProcessModules
constexpr size_t PROCESS_ENUM_RESERVE   = 1024;              // Reserve capacity for process snapshots
constexpr size_t WINDOW_TITLE_MAX       = 256;               // Overlay window title buffer
constexpr size_t CHUNK_SIZE             = 4096;              // Integrity hashing chunk size
constexpr size_t SIGNATURE_SCAN_MAX     = 16 * 1024 * 1024;  // Max bytes scanned for signature scan
constexpr size_t CAPTURE_MAX            = 256;               // Syscall stub capture length

}
