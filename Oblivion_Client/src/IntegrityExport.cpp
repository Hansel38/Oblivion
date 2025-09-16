#include "../pch.h"
#include "../include/IntegrityExport.h"
#include "../include/IntegrityTelemetry.h"
#include "../include/TcpClient.h"
#include "../include/Config.h"
#include "../include/Logger.h"
#include "../include/StringUtil.h"
#include "../include/ExportHmacKey.h"
#include "../include/HashUtil.h"
#include <sstream>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

namespace OblivionEye {

IntegrityExport& IntegrityExport::Instance(){ static IntegrityExport s; return s; }

IntegrityExport::IntegrityExport(){
    m_enabled.store(OblivionEye::Config::INTEGRITY_EXPORT_ENABLED_DEFAULT);
    m_intervalMs.store(OblivionEye::Config::INTEGRITY_EXPORT_INTERVAL_MS_DEFAULT);
    m_lastSend = std::chrono::steady_clock::now();
}

void IntegrityExport::SetEnabled(bool en){ m_enabled.store(en); if(en) m_lastSend = std::chrono::steady_clock::now() - std::chrono::milliseconds(m_intervalMs.load()); }
void IntegrityExport::SetIntervalMs(unsigned ms){ if(ms < 1000) ms = 1000; m_intervalMs.store(ms); }

std::wstring IntegrityExport::BuildJsonSnapshot() const {
    std::wstring modules[4] = {L"ntdll.dll", L"kernel32.dll", L"user32.dll", L"gdi32.dll"};
    std::wstringstream js; js<<L"{"; bool first=true; for(auto &m: modules){ auto st=IntegrityTelemetry::Instance().Get(m); if(!first) js<<L","; first=false; js<<L"\""<<m<<L"\":{"
        <<L"\"baselineLoadsOk\":"<<st.baselineLoadsOk
        <<L",\"hmacMismatch\":"<<st.hmacMismatch
        <<L",\"rebaselineCount\":"<<st.rebaselineCount
        <<L",\"manualRebaselineCount\":"<<st.manualRebaselineCount
        <<L",\"chainAdvanceCount\":"<<st.chainAdvanceCount
        <<L",\"autoWhitelistCount\":"<<st.autoWhitelistCount
        <<L",\"verifyNowRequests\":"<<st.verifyNowRequests
        <<L",\"forceVerifyFailures\":"<<st.forceVerifyFailures
        <<L",\"totalChunks\":"<<st.totalChunks
        <<L",\"whitelistedChunks\":"<<st.whitelistedChunks
        <<L",\"hmacValid\":"<<(st.hmacValid?1:0)
        <<L",\"chainDepth\":"<<st.chainDepth
        <<L",\"lastBaselineTime\":\""<<(st.lastBaselineTime.empty()?L"":st.lastBaselineTime)<<L"\""
        <<L",\"lastAutoWhitelistTime\":\""<<(st.lastAutoWhitelistTime.empty()?L"":st.lastAutoWhitelistTime)<<L"\""
        <<L",\"lastManualRebaselineTime\":\""<<(st.lastManualRebaselineTime.empty()?L"":st.lastManualRebaselineTime)<<L"\"";
        js<<L"}"; }
    js<<L"}"; auto w = js.str(); if(w.size() > OblivionEye::Config::INTEGRITY_EXPORT_MAX_JSON){ w.resize(OblivionEye::Config::INTEGRITY_EXPORT_MAX_JSON); }
    return w;
}

static std::string Sha256Hex(const unsigned char* data, size_t len){
    // Reuse HashUtil::Sha256Trunc64 not sufficient (we need full hash). Implement lightweight wrapper using Windows CNG? For now simple fallback: feed into existing sha256 inside HashUtil if available.
    // Placeholder: since HashUtil only exposes truncated variant in this codebase snippet, we implement a minimal SHA256 (optionally replace with platform). For brevity, we skip full implementation here if already present elsewhere.
    // NOTE: If full SHA-256 util exists, replace this with that call. Here we return empty to avoid heavy inline code (user can extend).
    return std::string();
}

// Helper: HMAC-SHA256 via CNG, returns 64 hex lower (empty on fail)
static std::string HmacSha256HexLower(const std::string &key, const std::string &data){
    BCRYPT_ALG_HANDLE hAlg=nullptr; BCRYPT_HASH_HANDLE hHash=nullptr; NTSTATUS st;
    if((st=BCryptOpenAlgorithmProvider(&hAlg,BCRYPT_SHA256_ALGORITHM,nullptr,BCRYPT_ALG_HANDLE_HMAC_FLAG))!=0) return {};
    DWORD objLen=0, cb=0, hashLen=0; unsigned char *obj=nullptr; unsigned char hash[32];
    st = BCryptGetProperty(hAlg,BCRYPT_OBJECT_LENGTH,(PUCHAR)&objLen,sizeof(objLen),&cb,0); if(st!=0){ BCryptCloseAlgorithmProvider(hAlg,0); return {}; }
    st = BCryptGetProperty(hAlg,BCRYPT_HASH_LENGTH,(PUCHAR)&hashLen,sizeof(hashLen),&cb,0); if(st!=0 || hashLen!=32){ BCryptCloseAlgorithmProvider(hAlg,0); return {}; }
    obj = (unsigned char*)HeapAlloc(GetProcessHeap(),0,objLen); if(!obj){ BCryptCloseAlgorithmProvider(hAlg,0); return {}; }
    st = BCryptCreateHash(hAlg,&hHash,obj,objLen,(PUCHAR)key.data(),(ULONG)key.size(),0);
    if(st==0) st = BCryptHashData(hHash,(PUCHAR)data.data(),(ULONG)data.size(),0);
    if(st==0) st = BCryptFinishHash(hHash,hash,32,0);
    if(hHash) BCryptDestroyHash(hHash); if(hAlg) BCryptCloseAlgorithmProvider(hAlg,0); if(obj) HeapFree(GetProcessHeap(),0,obj);
    if(st!=0) return {};
    static const char* hx="0123456789abcdef"; std::string out; out.resize(64);
    for(int i=0;i<32;++i){ out[i*2]=hx[(hash[i]>>4)&0xF]; out[i*2+1]=hx[hash[i]&0xF]; }
    return out;
}

void IntegrityExport::DoSend(const std::wstring& json){
    EnsureSession();
    unsigned long long seq = ++m_seq; // increment atomically then capture
    std::wstringstream prefix;
    prefix << L"INTSTAT|sid=" << m_sessionId << L"|seq=" << seq << L"|";
    std::wstring core = prefix.str() + json; // base payload dengan sid & seq
    auto utf8Core = StringUtil::WideToUtf8(core);
    if(m_hmacEnabled.load()){
        auto key = ExportHmacKey::Instance().GetUtf8();
        auto hmac = HmacSha256HexLower(key, utf8Core);
        if(hmac.empty()){
            // gagal HMAC
            if(m_hmacRequire.load()){
                // jika required: tandai drop untuk visibilitas (tidak kirim frame tanpa HMAC)
                LogErr(L"IntegrityExport HMAC gagal - frame dibatalkan (require mode)");
                return;
            } else {
                unsigned long long weak = HashUtil::Sha256Trunc64(utf8Core.data(), utf8Core.size());
                char buf[17]; snprintf(buf,sizeof(buf),"%016llx",(unsigned long long)weak);
                utf8Core += "|X="; utf8Core += buf; utf8Core += "|ALG=weak";
            }
        } else {
            utf8Core += "|X="; utf8Core += hmac; utf8Core += "|ALG=hmac256";
        }
    } else if(m_hmacRequire.load()) {
        // require diaktifkan tapi HMAC disabled → tidak konsisten, log & batalkan
        LogErr(L"IntegrityExport HMAC_REQUIRE aktif tapi HMAC disabled - frame dibatalkan");
        return;
    }
    TcpClient::Instance().Send(utf8Core + "\n");
}

void IntegrityExport::EnsureSession(){
    if(!m_sessionId.empty()) return;
    unsigned char rnd[16];
    if(BCryptGenRandom(nullptr, rnd, sizeof(rnd), BCRYPT_USE_SYSTEM_PREFERRED_RNG)!=0){
        // fallback sederhana
        for(size_t i=0;i<sizeof(rnd);++i) rnd[i] = (unsigned char)(GetTickCount64() >> (i%8));
    }
    static const wchar_t* hex=L"0123456789abcdef";
    std::wstring sid; sid.resize(32);
    for(int i=0;i<16;++i){ sid[i*2]=hex[(rnd[i]>>4)&0xF]; sid[i*2+1]=hex[rnd[i]&0xF]; }
    m_sessionId = sid;
    m_seq.store(0);
}

void IntegrityExport::SendNow(){ if(!m_enabled.load()) return; auto json = BuildJsonSnapshot(); DoSend(json); m_lastSend = std::chrono::steady_clock::now(); }

void IntegrityExport::Tick(){ if(!m_enabled.load()) return; auto now = std::chrono::steady_clock::now(); auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - m_lastSend).count(); if((unsigned)elapsed >= m_intervalMs.load()){ SendNow(); } }

}
