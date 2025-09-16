#include "../pch.h"
#include "../include/ExportHmacKey.h"
#include "../include/Config.h"
#include "../include/StringUtil.h"
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

namespace OblivionEye {
ExportHmacKey& ExportHmacKey::Instance(){ static ExportHmacKey s; return s; }
ExportHmacKey::ExportHmacKey(){
    // default derive from PIPE_SHARED_KEY (convert wide to utf8)
    m_keyUtf8 = StringUtil::WideToUtf8(Config::PIPE_SHARED_KEY);
    m_lastRotation = std::chrono::steady_clock::now();
}
void ExportHmacKey::SetFromUtf8(const std::string& k){ if(k.empty()) return; std::lock_guard<std::mutex> lk(m_mtx); m_keyUtf8 = k; }
std::string ExportHmacKey::GetUtf8() const { std::lock_guard<std::mutex> lk(m_mtx); return m_keyUtf8; }

bool ExportHmacKey::RotateRandom(){
    unsigned char buf[32];
    if(BCryptGenRandom(nullptr, buf, sizeof(buf), BCRYPT_USE_SYSTEM_PREFERRED_RNG)!=0){
        for(size_t i=0;i<sizeof(buf);++i) buf[i] = (unsigned char)(GetTickCount64() >> (i%8));
    }
    static const char* hx = "0123456789abcdef"; std::string hex; hex.resize(64);
    for(int i=0;i<32;++i){ hex[i*2]=hx[(buf[i]>>4)&0xF]; hex[i*2+1]=hx[buf[i]&0xF]; }
    {
        std::lock_guard<std::mutex> lk(m_mtx); m_keyUtf8 = hex; }
    // catat waktu rotasi (UTC iso ringkas)
    SYSTEMTIME st; GetSystemTime(&st); wchar_t wbuf[64]; swprintf(wbuf,64,L"%04u-%02u-%02uT%02u:%02u:%02uZ",st.wYear,st.wMonth,st.wDay,st.wHour,st.wMinute,st.wSecond);
    m_lastRotationIso = wbuf;
    m_lastRotation = std::chrono::steady_clock::now();
    return true;
}

void ExportHmacKey::Tick(){
    unsigned iv = m_rotationIntervalMs.load(); if(!iv) return; auto now = std::chrono::steady_clock::now();
    if(std::chrono::duration_cast<std::chrono::milliseconds>(now - m_lastRotation).count() >= iv){ RotateRandom(); }
}

std::wstring ExportHmacKey::GetLastRotationTime() const { return m_lastRotationIso; }
}
