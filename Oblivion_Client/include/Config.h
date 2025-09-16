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

// Cheat Engine heuristic (OverlayScanner) tunables
constexpr int    CE_MIN_WIDTH           = 400;   // Minimal window width considered
constexpr int    CE_MIN_HEIGHT          = 300;   // Minimal window height considered
constexpr int    CE_SCORE_THRESHOLD     = 4;     // Score to trigger detection
constexpr unsigned long long CE_COOLDOWN_MS = 5ull*60ull*1000ull; // Global cooldown between CE heuristic reports
constexpr int    CE_REQ_LISTS           = 2;     // ListView count adding score
constexpr int    CE_REQ_EDITS           = 8;     // Edit control count adding score
constexpr int    CE_UI_HITS_SCORE1      = 2;     // UI keyword hits threshold for +1
constexpr int    CE_UI_HITS_SCORE2      = 4;     // Additional UI hits threshold for +1 extra
constexpr int    CE_EARLYSTOP_UI        = 3;     // Early-stop UI hits (with others) for short-circuit
constexpr int    CE_EARLYSTOP_LISTS     = 2;     // Early-stop listview minimum
constexpr int    CE_EARLYSTOP_EDITS     = 6;     // Early-stop edits minimum

// External intrusive handle scan
constexpr unsigned HANDLE_SCAN_COOLDOWN_MS = 10000; // Minimum ms between full system handle scans
constexpr size_t   HANDLE_SCAN_MAX_DUP     = 32;     // Max duplicate suspicious entries to report (cap spam)

// Correlation engine tunables
constexpr unsigned CORR_WINDOW_MS          = 60000;  // Window waktu event tetap dihitung
constexpr unsigned CORR_PRUNE_INTERVAL_MS  = 5000;   // Interval minimal prune list event
constexpr unsigned CORR_SCORE_THRESHOLD    = 5;      // Skor trigger hook correlation (lama)
constexpr unsigned CORR_TRIGGER_DISTINCT   = 3;      // Distinct kategori minimal untuk trigger multi-source partial
constexpr unsigned CE_PARTIAL_SCORE        = 2;      // Skor diberikan untuk partial CE heuristic
constexpr unsigned SIG_PARTIAL_SCORE       = 2;      // Skor partial signature (misal 1 cluster string saja)
constexpr unsigned EXT_HANDLE_SCORE        = 3;      // Skor handle intrusif eksternal
constexpr unsigned CORR_STATUS_SNAPSHOT_MS = 1500;   // Interval minimal refresh evaluasi status pasif
constexpr unsigned CORR_DETECTION_COOLDOWN_MS = 10000; // Cooldown sebelum kombinasi detection correlation boleh dikirim lagi

// Pipe handshake / auth (lightweight; replace key in production build)
constexpr const wchar_t* PIPE_SHARED_KEY = L"OBLIVION_DEFAULT_KEY"; // placeholder shared secret
constexpr unsigned PIPE_HANDSHAKE_TIMEOUT_MS = 3000; // handshake timeout ms
constexpr bool     PIPE_HANDSHAKE_STRICT_DEFAULT = true;  // legacy fallback disabled by default
constexpr unsigned PIPE_HANDSHAKE_FAIL_WINDOW_MS = 60000;  // window untuk menghitung gagal
constexpr unsigned PIPE_HANDSHAKE_FAIL_MAX      = 8;       // maksimal gagal dalam window sebelum penalti
constexpr unsigned PIPE_HANDSHAKE_PENALTY_MS    = 5000;    // sleep ekstra sebelum coba lagi saat over-fail
constexpr bool     PIPE_HMAC_DEFAULT_ENABLED    = false;   // default HMAC payload dimatikan (aktifkan via command)
constexpr bool     PIPE_HMAC_REQUIRED_DEFAULT   = false;   // server mewajibkan HMAC (akan enforce setelah verifikasi sisi server siap)
constexpr unsigned PIPE_REPLAY_WINDOW_MS       = 30000;    // window waktu nonce/log id dianggap masih valid untuk deteksi replay
constexpr size_t   PIPE_REPLAY_CACHE_MAX       = 4096;     // maksimum entri cache nonce/log untuk replay guard sebelum prune
constexpr bool     LOG_HANDSHAKE_STRICT_DEFAULT = true;    // server log now requires HELLO (no legacy)

// Sequence number enforcement (ordering + stronger replay semantics)
constexpr bool     PIPE_SEQ_ENFORCE_DEFAULT    = true;    // Drop out-of-order or missing sequence
constexpr bool     PIPE_SEQ_WARN_ONLY_DEFAULT  = false;   // If true and enforce also true? (Future). For now use to disable drops by setting ENFORCE false.

// Runtime command security
constexpr bool     PIPE_SET_REQUIRE_HMAC       = true;    // When true, server will only honor #SET lines if current hmacRequired is true and packet carried valid HMAC

// Security event rate limiting (server-side SecEvent suppression)
constexpr unsigned SEC_EVT_RATE_WINDOW_MS     = 5000;     // Sliding window length for burst detection
constexpr unsigned SEC_EVT_RATE_THRESHOLD     = 25;       // Events per window before suppression starts
constexpr unsigned SEC_EVT_RATE_RESUME_PCT    = 60;       // Resume emission when count in window drops below this % of threshold

// Security event persistence (server side)
constexpr bool     LOG_EVENT_PERSIST_ENABLED_DEFAULT = false;      // Disabled by default; enable via future #SET LOGPERSIST=1
constexpr const wchar_t* LOG_EVENT_FILE_BASENAME     = L"SecEvents"; // Base filename; rotation adds .NNN.jsonl
constexpr size_t   LOG_EVENT_MAX_BYTES               = 512 * 1024;  // Rotate after ~512KB per file
constexpr unsigned LOG_EVENT_MAX_ROTATIONS           = 5;           // Keep last 5 files (0..4), oldest overwritten in ring

// Memory module section integrity (phase 1)
constexpr unsigned MEM_SEC_INTEGRITY_INTERVAL_MS = 7000;   // Interval antar pemeriksaan (ms)
constexpr unsigned MEM_SEC_MAX_SECTIONS          = 16;     // Batas maksimal section yang dicatat per modul
constexpr const wchar_t* MEM_SEC_HASH_ALGO       = L"SHA256"; // Placeholder (bisa perlu variasi algoritma ke depan)

// Integrity baseline security enhancements
constexpr bool     INTEGRITY_HMAC_HWID_ENABLED_DEFAULT = true;   // Derive HMAC key from HWID (added to obfuscated static key)
constexpr bool     INTEGRITY_CHAIN_BASELINE_DEFAULT    = true;   // Chain new baseline HMAC with previous to resist poisoning
constexpr bool     MODSEC_AUDIT_MODE_DEFAULT           = false;  // When true detections are logged only (no termination)
constexpr unsigned INTEGRITY_BASELINE_VERSION          = 2;      // Versioned baseline format (upgrade path aware)
constexpr bool     INTEGRITY_AUTO_WHITELIST_DISK_MATCH_DEFAULT = false; // If true, chunks that differ from old baseline but equal clean disk are auto-whitelisted & baseline refreshed.

}
