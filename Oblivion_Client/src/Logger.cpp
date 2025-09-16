#include "../pch.h"
#include "../include/Logger.h"
#include <windows.h>
#include <chrono>
#include <string>

namespace OblivionEye {

static std::wstring LevelTag(LogLevel l){
    switch(l){
        case LogLevel::Debug: return L"DBG"; case LogLevel::Info: return L"INF";
        case LogLevel::Warn: return L"WRN"; case LogLevel::Error: return L"ERR"; case LogLevel::Security: return L"SEC";
    }
    return L"UNK";
}

LoggerBackend &LoggerBackend::Instance(){ static LoggerBackend inst; return inst; }

void LoggerBackend::SetLevel(LogLevel lvl){ std::lock_guard<std::mutex> lk(m_mtx); m_level = lvl; }
LogLevel LoggerBackend::GetLevel() const { return m_level; }

void LoggerBackend::SetMaxRing(size_t n){ std::lock_guard<std::mutex> lk(m_mtx); if(n==0) n=1; m_ringMax = n; if(m_ring.size()>m_ringMax) m_ring.resize(m_ringMax); if(m_ringIndex>=m_ringMax) m_ringIndex=0; }

void LoggerBackend::EnableFileSink(const std::wstring &path, bool append){
    std::lock_guard<std::mutex> lk(m_mtx);
    if(m_fileHandle){ CloseHandle((HANDLE)m_fileHandle); m_fileHandle=nullptr; }
    DWORD disp = append ? OPEN_ALWAYS : CREATE_ALWAYS;
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, disp, FILE_ATTRIBUTE_NORMAL, nullptr);
    if(h==INVALID_HANDLE_VALUE) return; // silently ignore
    if(append){ SetFilePointer(h, 0, nullptr, FILE_END); }
    m_fileHandle = h;
}

void LoggerBackend::DisableFileSink(){ std::lock_guard<std::mutex> lk(m_mtx); if(m_fileHandle){ CloseHandle((HANDLE)m_fileHandle); m_fileHandle=nullptr; } }

void LoggerBackend::WriteFileLine(const std::wstring &line){
    if(!m_fileHandle) return; std::wstring withNL = line + L"\r\n"; DWORD written=0; WriteFile((HANDLE)m_fileHandle, withNL.c_str(), (DWORD)(withNL.size()*sizeof(wchar_t)), &written, nullptr);
}

void LoggerBackend::Push(LogLevel lvl, const std::wstring &msg){
    unsigned long long tick = GetTickCount64();
    {
        std::lock_guard<std::mutex> lk(m_mtx);
        if((int)lvl < (int)m_level) return; // filtered
        if(m_ring.size() < m_ringMax) m_ring.push_back({tick,lvl,msg});
        else {
            m_ring[m_ringIndex] = {tick,lvl,msg};
            m_ringIndex = (m_ringIndex + 1) % m_ringMax;
        }
        std::wstring line = L"[OblivionEye] ["+LevelTag(lvl)+L"] "+msg;
        OutputDebugStringW((line + L"\n").c_str());
        WriteFileLine(line);
    }
}

std::vector<LogEntry> LoggerBackend::Snapshot(){
    std::lock_guard<std::mutex> lk(m_mtx);
    std::vector<LogEntry> out;
    if(m_ring.size()<m_ringMax || m_ringIndex==0){
        out = m_ring; // already linear
    } else {
        // reorder circular into chronological
        out.reserve(m_ring.size());
        for(size_t i=m_ringIndex;i<m_ring.size();++i) out.push_back(m_ring[i]);
        for(size_t i=0;i<m_ringIndex;++i) out.push_back(m_ring[i]);
    }
    return out;
}

// Backward wrappers
void Log(const std::wstring &msg){ LoggerBackend::Instance().Push(LogLevel::Info, msg); }
void LogDbg(const std::wstring &msg){ LoggerBackend::Instance().Push(LogLevel::Debug, msg); }
void LogWarn(const std::wstring &msg){ LoggerBackend::Instance().Push(LogLevel::Warn, msg); }
void LogErr(const std::wstring &msg){ LoggerBackend::Instance().Push(LogLevel::Error, msg); }
void LogSec(const std::wstring &msg){ LoggerBackend::Instance().Push(LogLevel::Security, msg); }

} // namespace OblivionEye
