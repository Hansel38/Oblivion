#define NOMINMAX
#include <windows.h>
#include <string>
#include <iostream>
#include <vector>
#include <cstdint>
#include <unordered_set>
#include <unordered_map>
#include <deque>
#include <sstream>
#include <iomanip>
#include <thread>
#include <chrono>
#include "../include/PipeServer.h"
#include "../../Oblivion_Client/include/Config.h" // reuse shared key constant
#include "../../Oblivion_Client/include/HashUtil.h"

// Safe UTF-8 conversion (avoids implicit wchar_t->char narrowing warning)
static std::string WideToUtf8(const std::wstring &w) {
    if(w.empty()) return {};
    int needed = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    if(needed <= 0) return {};
    std::string out; out.resize(needed);
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), out.data(), needed, nullptr, nullptr);
    return out;
}

// Simple event counter registry (not thread-safe; single-threaded loop).
static std::unordered_map<std::string, uint64_t> g_eventCounters;

static thread_local std::string g_sessionId; // per-connection/session scope

// Rate limiting state
struct RateBucket {
    std::deque<DWORD> stamps; // timestamps of events in window
    bool suppress = false;
    uint64_t suppressedCount = 0; // number suppressed during current suppression
    uint64_t lifetimeTotal = 0;   // total suppressed across all suppression phases
};
static std::unordered_map<std::string, RateBucket> g_rate;
// Mutable runtime-adjustable rate limit parameters (initialized from Config at first use)
static unsigned g_rl_window_ms = OblivionEye::Config::SEC_EVT_RATE_WINDOW_MS;
static unsigned g_rl_threshold = OblivionEye::Config::SEC_EVT_RATE_THRESHOLD;
static unsigned g_rl_resume_pct = OblivionEye::Config::SEC_EVT_RATE_RESUME_PCT; // percent of threshold

// Persistent security event logging (simple size-rotation ring)
static bool     g_logPersistEnabled = OblivionEye::Config::LOG_EVENT_PERSIST_ENABLED_DEFAULT;
static unsigned g_logCurrentIndex = 0; // rotation index
static uint64_t g_logCurrentSize = 0;  // bytes written to current file

static std::wstring BuildLogFilePath(unsigned index) {
    std::wstringstream ws; ws << OblivionEye::Config::LOG_EVENT_FILE_BASENAME << L"." << index << L".jsonl"; return ws.str();
}

static void RotateLogFileIfNeeded(size_t incomingLen) {
    if(!g_logPersistEnabled) return;
    if(g_logCurrentSize + incomingLen <= OblivionEye::Config::LOG_EVENT_MAX_BYTES) return;
    g_logCurrentIndex = (g_logCurrentIndex + 1) % (OblivionEye::Config::LOG_EVENT_MAX_ROTATIONS);
    // Truncate new file
    std::wstring path = BuildLogFilePath(g_logCurrentIndex);
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if(h != INVALID_HANDLE_VALUE) { CloseHandle(h); }
    g_logCurrentSize = 0;
}

static void AppendPersistent(const std::string &line) {
    if(!g_logPersistEnabled) return;
    RotateLogFileIfNeeded(line.size()+1);
    std::wstring path = BuildLogFilePath(g_logCurrentIndex);
    HANDLE h = CreateFileW(path.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if(h == INVALID_HANDLE_VALUE) return;
    DWORD written=0; WriteFile(h, line.c_str(), (DWORD)line.size(), &written, nullptr);
    WriteFile(h, "\n", 1, &written, nullptr);
    g_logCurrentSize += written + 1;
    CloseHandle(h);
}

static bool IsRateLimitedEvent(const std::string &evt) {
    return evt=="HMAC_FAIL" || evt=="REPLAY_DROP" || evt=="SEQ_FAIL" || evt=="SEQ_WARN" || evt=="SEQ_GAP"; // adjustable list
}

static void SecEvent(const std::string &evt, std::initializer_list<std::pair<std::string,std::string>> kv) {
    g_eventCounters[evt]++;
    DWORD now = GetTickCount();
    if(IsRateLimitedEvent(evt)) {
        auto &bucket = g_rate[evt];
        // prune window
        while(!bucket.stamps.empty() && now - bucket.stamps.front() > g_rl_window_ms) bucket.stamps.pop_front();
        bucket.stamps.push_back(now);
        unsigned threshold = g_rl_threshold;
        if(!bucket.suppress && bucket.stamps.size() > threshold) {
            bucket.suppress = true; bucket.suppressedCount = 0;
            // emit suppression start event
            std::ostringstream oss; oss << "{\"evt\":\"RATE_SUPPRESS_START\",\"tick\":" << now; if(!g_sessionId.empty()) oss << ",\"sessionId\":\""<<g_sessionId<<"\""; oss << ",\"target\":\""<<evt<<"\",\"countWindow\":\""<<bucket.stamps.size()<<"\"}"; std::cout<<oss.str()<<std::endl;
        }
        if(bucket.suppress) {
            bucket.suppressedCount++;
            bucket.lifetimeTotal++;
            // compute resume threshold
            unsigned resumeBelow = (threshold * g_rl_resume_pct)/100;
            if(bucket.stamps.size() <= resumeBelow) {
                // emit summary + resume
                std::ostringstream os; os << "{\"evt\":\"RATE_SUPPRESS_SUMMARY\",\"tick\":"<<now; if(!g_sessionId.empty()) os << ",\"sessionId\":\""<<g_sessionId<<"\""; os << ",\"target\":\""<<evt<<"\",\"suppressed\":\""<<bucket.suppressedCount<<"\"}"; std::cout<<os.str()<<std::endl;
                bucket.suppress = false; bucket.suppressedCount = 0;
            } else {
                return; // DROP original event while suppressed
            }
        }
    }
    std::ostringstream oss; oss << "{\"evt\":\"" << evt << "\"";
    oss << ",\"tick\":" << now;
    if(!g_sessionId.empty()) oss << ",\"sessionId\":\"" << g_sessionId << "\"";
    for (auto &p : kv) {
        oss << ",\"" << p.first << "\":\"";
        for(char c: p.second) { if(c=='"' || c=='\\') oss << '\\' << c; else if((unsigned char)c < 32) oss << '?'; else oss << c; }
        oss << "\"";
    }
    oss << "}"; std::string lineOut = oss.str();
    std::cout << lineOut << std::endl;
    AppendPersistent(lineOut);
}

static std::string BuildStateJson(bool hmacRequired, bool seqEnforce, uint64_t lastSeq, bool hasSeqBaseline, size_t replaySize) {
    std::ostringstream oss; oss << "{\"evt\":\"STATE\"";
    oss << ",\"tick\":" << GetTickCount();
    if(!g_sessionId.empty()) oss << ",\"sessionId\":\"" << g_sessionId << "\"";
    oss << ",\"hmacRequired\":\"" << (hmacRequired?"1":"0") << "\"";
    oss << ",\"seqEnforce\":\"" << (seqEnforce?"1":"0") << "\"";
    oss << ",\"hasSeqBaseline\":\"" << (hasSeqBaseline?"1":"0") << "\"";
    if(hasSeqBaseline) oss << ",\"lastSeq\":\"" << lastSeq << "\"";
    oss << ",\"replayCache\":\"" << replaySize << "\"";
    // Flatten counters with prefix c_<name>
    for(auto &p : g_eventCounters) {
        oss << ",\"c_"; // key prefix
        // sanitize key (only allow alnum + underscore)
        for(char c: p.first) {
            if((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='_') oss<<c; else oss<<'_';
        }
        oss << "\":\"" << p.second << "\"";
    }
    // Rate limiting state snapshot
    // Collect summary: number of buckets currently in suppression and per-bucket details
    size_t activeSuppress = 0; for(auto &rb : g_rate) if(rb.second.suppress) activeSuppress++;
    oss << ",\"rl_active\":\"" << activeSuppress << "\"";
    // Include current rate limit configuration (for observability / remote tuning verification)
    oss << ",\"rl_thr\":\"" << g_rl_threshold << "\"";
    oss << ",\"rl_win\":\"" << g_rl_window_ms << "\"";
    oss << ",\"rl_resume\":\"" << g_rl_resume_pct << "\"";
    oss << ",\"logPersist\":\"" << (g_logPersistEnabled?"1":"0") << "\"";
    // Build rl array: rl is a JSON array of objects with evt, suppress (0/1), window (current stamps size), suppressed (count during this suppression phase)
    oss << ",\"rl\":[";
    bool first=true; for(auto &rb : g_rate) {
        if(!first) oss << ','; first=false;
        oss << "{\"evt\":\"";
        // sanitize event name
        for(char c: rb.first) { if((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='_') oss<<c; else oss<<'_'; }
        oss << "\",\"suppress\":\"" << (rb.second.suppress?"1":"0") << "\"";
        oss << ",\"window\":\"" << rb.second.stamps.size() << "\"";
    if(rb.second.suppress) oss << ",\"suppressed\":\"" << rb.second.suppressedCount << "\""; else oss << ",\"suppressed\":\"0\"";
    oss << ",\"totalSupp\":\"" << rb.second.lifetimeTotal << "\"";
        oss << "}";
    }
    oss << "]";
    oss << "}"; return oss.str();
}

static uint32_t CalcCrc32(const uint8_t* data, size_t len) {
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; ++i) {
        crc ^= data[i];
        for (int b = 0; b < 8; ++b) {
            uint32_t bit = crc & 1u; crc >>= 1; if (bit) crc ^= 0xEDB88320u;
        }
    }
    return ~crc;
}

static bool VerifyAndStripCrc(std::string& msg) {
    size_t pos = msg.rfind("|CRC="); if (pos == std::string::npos) return true; std::string body = msg.substr(0,pos); std::string crcPart = msg.substr(pos+5); if (crcPart.size()!=8) return false; uint32_t claimed=0; std::stringstream ss; ss<<std::hex<<crcPart; ss>>claimed; uint32_t calc = CalcCrc32(reinterpret_cast<const uint8_t*>(body.data()), body.size()); if (calc!=claimed) return false; msg=body; return true;
}

static std::string ApplyRollingXor(const std::string& in, uint8_t baseKey, uint32_t nonce) {
    if (baseKey == 0) return in;
    std::string out = in;
    for (size_t i = 0; i < out.size(); ++i) {
        uint8_t dynamicPart = static_cast<uint8_t>((nonce >> (i % 24)) & 0xFF);
        uint8_t k = static_cast<uint8_t>(baseKey ^ dynamicPart ^ (uint8_t)(i * 31));
        out[i] = static_cast<char>(out[i] ^ k);
    }
    return out;
}

static bool ReadLineWithTimeout(HANDLE hPipe, std::string &out, DWORD timeoutMs) {
    out.clear();
    char ch; DWORD rd = 0; BOOL okB; DWORD start = GetTickCount();
    while (GetTickCount() - start < timeoutMs) {
        okB = ReadFile(hPipe, &ch, 1, &rd, nullptr);
        if (!okB || rd == 0) { Sleep(10); continue; }
        if (ch == '\n') return true;
        out.push_back(ch);
        if (out.size() > 512) break; // sanity guard
    }
    return false;
}

int RunPipeServer() {
    const wchar_t* pipeName = L"\\\\.\\pipe\\OblivionEye";
    std::wcout << L"[Server] Starting Named Pipe server at " << pipeName << std::endl;

    HANDLE hPipe = CreateNamedPipeW(pipeName, PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, 1, 0, 4096, 0, nullptr);
    if (hPipe == INVALID_HANDLE_VALUE) { std::wcerr << L"[Server] CreateNamedPipe failed.\n"; return 1; }

    std::wcout << L"[Server] Waiting for client...\n";
    BOOL connected = ConnectNamedPipe(hPipe, nullptr) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
    if (!connected) { std::wcerr << L"[Server] ConnectNamedPipe failed.\n"; CloseHandle(hPipe); return 1; }

    std::wstring sharedKeyW = OblivionEye::Config::PIPE_SHARED_KEY;
    std::string sharedKeyUtf8 = WideToUtf8(sharedKeyW); // explicit UTF-8 conversion

    // Handshake: expect HELLO <nonceCliHex> (line terminated by \n)

    std::string line;
    if(!ReadLineWithTimeout(hPipe, line, OblivionEye::Config::PIPE_HANDSHAKE_TIMEOUT_MS)) { std::wcerr<<L"[Server] Handshake timeout (HELLO)\n"; SecEvent("HANDSHAKE_FAIL", {{"reason","TIMEOUT_HELLO"}}); CloseHandle(hPipe); return 1; }
    bool legacy = false;
    std::string nonceCliHex;
    if(line.rfind("HELLO ",0)==0) {
        nonceCliHex = line.substr(6);
    } else {
        legacy = true; // would be legacy path if allowed
        if(OblivionEye::Config::PIPE_HANDSHAKE_STRICT_DEFAULT || OblivionEye::Config::LOG_HANDSHAKE_STRICT_DEFAULT) {
            std::wcerr<<L"[Server] Legacy handshake disallowed (strict mode)\n";
            CloseHandle(hPipe);
            return 1;
        }
    }

    std::string sessionKey;
    g_sessionId.clear();
    std::string nonceSrvHex;
    if(!legacy) {
        unsigned long long nonceSrv=0;
        if(BCryptGenRandom(nullptr,(PUCHAR)&nonceSrv,sizeof(nonceSrv),BCRYPT_USE_SYSTEM_PREFERRED_RNG)!=0) {
            nonceSrv = ((unsigned long long)GetTickCount64()<<16) ^ (uintptr_t)hPipe;
        }
        {
            std::ostringstream oss; oss<<std::hex<<nonceSrv; nonceSrvHex = oss.str();
        }
        std::string challenge = std::string("CHALLENGE ") + nonceSrvHex + "\n";
        DWORD written=0; WriteFile(hPipe, challenge.c_str(), (DWORD)challenge.size(), &written, nullptr);
    if(!ReadLineWithTimeout(hPipe, line, OblivionEye::Config::PIPE_HANDSHAKE_TIMEOUT_MS)) { std::wcerr<<L"[Server] Handshake timeout (AUTH)\n"; CloseHandle(hPipe); return 1; }
    if(line.rfind("AUTH ",0)!=0) { std::wcerr<<L"[Server] Invalid AUTH format\n"; SecEvent("HANDSHAKE_FAIL", {{"reason","BAD_AUTH_FORMAT"}}); CloseHandle(hPipe); return 1; }
        std::string digestHex = line.substr(5);
        std::string expected = OblivionEye::HashUtil::Sha256HexLower(sharedKeyUtf8 + nonceCliHex + nonceSrvHex);
        if(digestHex != expected) {
            SecEvent("HANDSHAKE_FAIL", {{"reason","BAD_DIGEST"}});
            DWORD w=0; std::string fail = "FAIL\n"; WriteFile(hPipe, fail.c_str(), (DWORD)fail.size(), &w, nullptr); std::wcerr<<L"[Server] Handshake FAIL\n"; CloseHandle(hPipe); return 1;
        }
        // Derive session key
        sessionKey = OblivionEye::HashUtil::Sha256HexLower(sharedKeyUtf8 + nonceCliHex + nonceSrvHex);
        // Generate 128-bit sessionId (hex)
        unsigned char sidBytes[16];
        if(BCryptGenRandom(nullptr, sidBytes, sizeof(sidBytes), BCRYPT_USE_SYSTEM_PREFERRED_RNG)!=0) {
            // fallback: use tick + handle entropy
            unsigned long long a = GetTickCount64();
            unsigned long long b = (unsigned long long)(uintptr_t)hPipe ^ ((unsigned long long)rand()<<32);
            memcpy(sidBytes, &a, 8); memcpy(sidBytes+8, &b, 8);
        }
        std::ostringstream sid;
        for(size_t i=0;i<sizeof(sidBytes);++i){ sid<<std::hex<<std::setw(2)<<std::setfill('0')<<(int)sidBytes[i]; }
        g_sessionId = sid.str();
    // Decide if HMAC required (config-driven)
    bool requireHmac = OblivionEye::Config::PIPE_HMAC_REQUIRED_DEFAULT;
    DWORD w=0; std::string ok = requireHmac? ("OK HMAC SESSIONID="+g_sessionId+"\n") : ("OK SESSIONID="+g_sessionId+"\n"); WriteFile(hPipe, ok.c_str(), (DWORD)ok.size(), &w, nullptr);
    std::wcout<<L"[Server] Handshake OK (session=" << g_sessionId.c_str() << L")" << (requireHmac? L" [HMAC REQUIRED]" : L"") << L"\n";
    SecEvent("HANDSHAKE_OK", {{"hmacRequired", requireHmac?"1":"0"}});
    } else {
        std::wcout<<L"[Server] Legacy client (no handshake) [ALLOWED - strict off]\n";
    }

    uint8_t baseKey = 0; // optional XOR (disabled by default if 0)
    bool rolling = true;
    bool expectCrc = false;
    bool hmacRequired = OblivionEye::Config::PIPE_HMAC_REQUIRED_DEFAULT; // enforced based on config
    bool seqEnforce = OblivionEye::Config::PIPE_SEQ_ENFORCE_DEFAULT;
    uint64_t lastSeq = 0; bool hasSeqBaseline = false;

    // Optimized replay cache: O(1) membership via unordered_set + chronological deque for pruning.
    struct ReplayEntry { uint32_t nonce; DWORD tick; };
    std::deque<ReplayEntry> replayQueue; // ordered by insertion/time
    std::unordered_set<uint32_t> replaySet; replaySet.reserve(512);

    std::wcout << L"[Server] Reading stream..." << std::endl;
    char buffer[2048]; DWORD read=0;
    while (ReadFile(hPipe, buffer, sizeof(buffer)-1, &read, nullptr)) {
        buffer[read] = '\0'; std::string packet(buffer, read);
        uint32_t nonce=0; bool parsedNonce=false;
        if (packet.rfind("NONCE=",0)==0) {
            if (packet.size() > 15 && packet[14]==';') {
                std::string hexNonce = packet.substr(6,8); std::stringstream ss; ss<<std::hex<<hexNonce; ss>>nonce; parsedNonce=true; packet.erase(0,15);
                // Replay prune + check (optimized)
                DWORD now = GetTickCount();
                // Evict expired entries from front
                while(!replayQueue.empty() && (now - replayQueue.front().tick > OblivionEye::Config::PIPE_REPLAY_WINDOW_MS)) {
                    replaySet.erase(replayQueue.front().nonce);
                    replayQueue.pop_front();
                }
                // Capacity guard: if still overflowing beyond max, force pop oldest
                while(replayQueue.size() > OblivionEye::Config::PIPE_REPLAY_CACHE_MAX) {
                    replaySet.erase(replayQueue.front().nonce);
                    replayQueue.pop_front();
                }
                if(replaySet.find(nonce) != replaySet.end()) {
                    std::ostringstream nhex; nhex<<std::hex<<nonce; SecEvent("REPLAY_DROP", {{"nonce", nhex.str()}});
                    std::cout << "[Client][REPLAY] nonce="<<std::hex<<nonce<<std::dec<<" dropped"<<std::endl; continue; }
                replayQueue.push_back({ nonce, now });
                replaySet.insert(nonce);
            }
        }
        std::string payload = packet;
        // Runtime control commands (plaintext, not transformed) start with #SET <KEY>=<0|1> or #DUMP STATE
        if(payload.rfind("#SET ",0)==0 || payload.rfind("#DUMP STATE",0)==0) {
            // Security: optionally require that current packet carried a valid HMAC (enforced after HMAC check below).
            // We'll temporarily store command and process after HMAC verification stage; mark flag.
            std::string setLine = payload; // keep full line
            // Defer handling until after HMAC (we need to know if HMAC present/valid). We'll process after HMAC section using setLine variable.
            // To simplify flow, handle minimal parse here once HMAC passes: we jump to label postHmacSet.
            // Inject a marker and proceed to standard HMAC path (no modifications to payload besides detection).
            bool allowedDirect = true; // legacy allow if config not requiring HMAC
            // We'll validate again after HMACOk.
            // Process after HMAC logic by using goto label; avoid duplicating code.
            // For clarity we reuse existing code path; set a flag.
            // Attach variable in outer scope via lambda static (not great but minimal invasive) -> Instead refactor quickly:
            static std::string pendingSet;
            pendingSet = setLine;
            // After HMAC verification branch we'll check pendingSet length.
            // Skip normal payload processing for now; continue to HMAC block with payload unchanged.
            // The payload itself should not include HMAC currently (client can send with HMAC to satisfy requirement).
            // We'll rely on existing hmacOk; if config requires HMAC for #SET and none present, reject.
            // Mark special prefix so we don't log as normal later.
            if(pendingSet.size()) {
                // We'll parse after hmacOk evaluation below.
            }
            // Fall through; do not 'continue' so HMAC logic can run.
        }
        if (rolling && parsedNonce) payload = ApplyRollingXor(payload, baseKey, nonce);
        bool crcOk=true; if(expectCrc) crcOk = VerifyAndStripCrc(payload); else VerifyAndStripCrc(payload);
        bool hmacOk = true;
        size_t hpos = payload.rfind("|H=");
        if(hpos != std::string::npos) {
            std::string withoutH = payload.substr(0,hpos);
            std::string hval = payload.substr(hpos+3);
            if(hval.size()==64) {
                std::string keyForHmac = sessionKey.empty()? sharedKeyUtf8 : sessionKey;
                std::string recompute = OblivionEye::HashUtil::Sha256HexLower(keyForHmac + withoutH);
                if(recompute != hval) hmacOk = false; else payload = withoutH;
            } else hmacOk=false;
        } else if(hmacRequired) hmacOk=false;
    if(!hmacOk) { SecEvent("HMAC_FAIL", {{"crcOk", crcOk?"1":"0"}}); std::cout << (crcOk?"[Client][HMACFAIL] ":"[Client][CRCFAIL][HMACFAIL] ") << payload << std::endl; continue; }
        // Post-HMAC #SET handling (if any)
        if(payload.rfind("#SET ",0)==0) {
            bool needHmacForSet = OblivionEye::Config::PIPE_SET_REQUIRE_HMAC;
            if(needHmacForSet && !hmacRequired) {
                // Policy: if requiring HMAC for #SET but global hmacRequired is off (server not enforcing), still demand presence of H tag (already validated above). If no H tag originally, we wouldn't get here because hmacOk false when required globally? Since global may be off, we separately check if original had H. Simplify: require presence of |H= earlier; if not present -> treat as reject.
            }
            // Parse command
            std::string cmd = payload.substr(5);
            size_t eq = cmd.find('=');
            if(eq==std::string::npos) { std::cout << "[Server][CFG][MALFORMED]" << std::endl; continue; }
            std::string key = cmd.substr(0,eq);
            std::string val = cmd.substr(eq+1);
            int ival = atoi(val.c_str()); bool flag = (ival!=0);
            if(needHmacForSet && hpos == std::string::npos) { SecEvent("CFG_DENY", {{"reason","NO_HMAC"},{"key",key}}); std::cout << "[Server][CFG][DENY][NOHMAC]" << std::endl; continue; }
            if(key == "HMACREQ") { hmacRequired = flag; SecEvent("CFG_SET", {{"key","HMACREQ"},{"value",flag?"1":"0"}}); std::cout << "[Server][CFG] HMACREQ="<<(hmacRequired?"1":"0")<< std::endl; }
            else if(key == "SEQENFORCE") { seqEnforce = flag; SecEvent("CFG_SET", {{"key","SEQENFORCE"},{"value",flag?"1":"0"}}); std::cout << "[Server][CFG] SEQENFORCE="<<(seqEnforce?"1":"0")<< std::endl; }
            else if(key == "RTHRESH") {
                if(ival <= 0 || ival > 100000) { SecEvent("CFG_DENY", {{"reason","RANGE"},{"key","RTHRESH"}}); std::cout << "[Server][CFG][DENY] RTHRESH range" << std::endl; }
                else { g_rl_threshold = (unsigned)ival; SecEvent("CFG_SET", {{"key","RTHRESH"},{"value",std::to_string(g_rl_threshold)}}); std::cout << "[Server][CFG] RTHRESH="<<g_rl_threshold<< std::endl; }
            }
            else if(key == "RWINMS") {
                if(ival < 100 || ival > 600000) { SecEvent("CFG_DENY", {{"reason","RANGE"},{"key","RWINMS"}}); std::cout << "[Server][CFG][DENY] RWINMS range" << std::endl; }
                else { g_rl_window_ms = (unsigned)ival; SecEvent("CFG_SET", {{"key","RWINMS"},{"value",std::to_string(g_rl_window_ms)}}); std::cout << "[Server][CFG] RWINMS="<<g_rl_window_ms<< std::endl; }
            }
            else if(key == "RRESUME") {
                if(ival <= 0 || ival >= 100) { SecEvent("CFG_DENY", {{"reason","RANGE"},{"key","RRESUME"}}); std::cout << "[Server][CFG][DENY] RRESUME range" << std::endl; }
                else { g_rl_resume_pct = (unsigned)ival; SecEvent("CFG_SET", {{"key","RRESUME"},{"value",std::to_string(g_rl_resume_pct)}}); std::cout << "[Server][CFG] RRESUME="<<g_rl_resume_pct<< std::endl; }
            }
            else if(key == "RLRESET") {
                if(flag) {
                    // gather summary before reset
                    size_t buckets = g_rate.size();
                    uint64_t totalLifetime=0; for(auto &kv : g_rate) totalLifetime += kv.second.lifetimeTotal;
                    g_rate.clear();
                    SecEvent("RATE_RESET", {{"buckets", std::to_string(buckets)}, {"totalSupp", std::to_string(totalLifetime)}});
                    std::cout << "[Server][CFG] RLRESET executed" << std::endl;
                } else {
                    SecEvent("CFG_DENY", {{"reason","ZERO"},{"key","RLRESET"}}); std::cout << "[Server][CFG][DENY] RLRESET=0" << std::endl;
                }
            }
            else if(key == "LOGPERSIST") {
                if(flag && !g_logPersistEnabled) {
                    g_logPersistEnabled = true; g_logCurrentIndex = 0; g_logCurrentSize = 0; // new session rotation start
                    // ensure first file truncated
                    std::wstring path = BuildLogFilePath(g_logCurrentIndex);
                    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
                    if(h!=INVALID_HANDLE_VALUE) CloseHandle(h);
                    SecEvent("CFG_SET", {{"key","LOGPERSIST"},{"value","1"}});
                    std::cout << "[Server][CFG] LOGPERSIST=1" << std::endl;
                } else if(!flag && g_logPersistEnabled) {
                    g_logPersistEnabled = false;
                    SecEvent("CFG_SET", {{"key","LOGPERSIST"},{"value","0"}});
                    std::cout << "[Server][CFG] LOGPERSIST=0" << std::endl;
                } else {
                    SecEvent("CFG_SET", {{"key","LOGPERSIST"},{"value", flag?"1":"0"}}); // idempotent
                }
            }
            else { SecEvent("CFG_UNKNOWN", {{"key",key}}); std::cout << "[Server][CFG][UNKNOWN] "<< key << std::endl; }
            continue; // processed control line
        }
        if(payload.rfind("#DUMP STATE",0)==0) {
            bool needHmacForSet = OblivionEye::Config::PIPE_SET_REQUIRE_HMAC;
            if(needHmacForSet && hpos == std::string::npos) { SecEvent("CFG_DENY", {{"reason","NO_HMAC"},{"key","DUMP_STATE"}}); std::cout << "[Server][STATE][DENY][NOHMAC]" << std::endl; continue; }
            std::string stateJson = BuildStateJson(hmacRequired, seqEnforce, lastSeq, hasSeqBaseline, replayQueue.size());
            // Emit as normal console line for human + structured event separate
            std::cout << "[Server][STATE] " << stateJson << std::endl;
            SecEvent("STATE_DUMP", {{"hmacRequired", hmacRequired?"1":"0"},{"seqEnforce", seqEnforce?"1":"0"}});
            continue;
        }
        // Parse sequence number (must appear as trailing segment like ...|SEQ=number)
        uint64_t seqVal = 0; bool seqFound=false; bool seqOk=true;
        size_t seqPos = payload.rfind("|SEQ=");
        if(seqPos != std::string::npos) {
            std::string seqPart = payload.substr(seqPos+5);
            if(!seqPart.empty() && seqPart.find('|')==std::string::npos) {
                // all digits?
                bool digits=true; for(char c: seqPart){ if(c<'0'||c>'9'){ digits=false; break; } }
                if(digits) {
                    try {
                        seqVal = std::stoull(seqPart);
                        seqFound = true;
                    } catch(...) { seqOk=false; }
                } else seqOk=false;
            } else seqOk=false;
            if(seqFound && seqOk) {
                if(!hasSeqBaseline) { hasSeqBaseline=true; lastSeq=seqVal; }
                else {
                    if(seqVal <= lastSeq) {
                        if(seqEnforce) { SecEvent("SEQ_FAIL", {{"type","ORDER"},{"seq",std::to_string(seqVal)},{"last",std::to_string(lastSeq)}}); std::cout << "[Client][SEQFAIL][ORDER] seq="<<seqVal<<" last="<<lastSeq<<" dropped"<< std::endl; continue; }
                        else { SecEvent("SEQ_WARN", {{"type","ORDER"},{"seq",std::to_string(seqVal)},{"last",std::to_string(lastSeq)}}); std::cout << "[Client][SEQWARN][ORDER] seq="<<seqVal<<" last="<<lastSeq<<""<< std::endl; }
                    } else if(seqVal > lastSeq + 1) {
                        SecEvent("SEQ_GAP", {{"expected",std::to_string(lastSeq+1)},{"got",std::to_string(seqVal)}}); std::cout << "[Client][SEQGAP] expected="<<(lastSeq+1)<<" got="<<seqVal<< std::endl;
                        lastSeq = seqVal; // accept but log gap
                    } else {
                        lastSeq = seqVal; // normal increment
                    }
                }
            } else {
                if(seqEnforce) { SecEvent("SEQ_FAIL", {{"type","MISSING"}}); std::cout << "[Client][SEQFAIL][MISSING] dropped" << std::endl; continue; }
                else { SecEvent("SEQ_WARN", {{"type","MISSING"}}); std::cout << "[Client][SEQWARN][MISSING]" << std::endl; }
            }
            if(seqFound) {
                payload.erase(seqPos); // strip |SEQ=... from final log output
            }
        } else {
            if(seqEnforce) { SecEvent("SEQ_FAIL", {{"type","ABSENT"}}); std::cout << "[Client][SEQFAIL][ABSENT] dropped" << std::endl; continue; }
            else { SecEvent("SEQ_WARN", {{"type","ABSENT"}}); std::cout << "[Client][SEQWARN][ABSENT]" << std::endl; }
        }

        std::cout << (crcOk?"[Client] ":"[Client][CRCFAIL] ") << payload << std::endl;
    }
    std::wcout << L"[Server] Client disconnected.\n"; CloseHandle(hPipe); return 0;
}
