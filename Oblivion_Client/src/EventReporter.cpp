#include "../pch.h"
#include "../include/EventReporter.h"
#include "../include/PipeClient.h"
#include <string>

namespace OblivionEye {
namespace EventReporter {

    static std::string WToUtf8(const std::wstring& w) {
        if (w.empty()) return {};
        int len = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, nullptr, 0, nullptr, nullptr);
        std::string out(len, '\0');
        WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, &out[0], len, nullptr, nullptr);
        return out;
    }

    void SendRaw(const std::string& line) {
        if (!PipeClient::Instance().IsRunning()) return;
        PipeClient::Instance().Send(line + "\n");
    }

    void SendDetection(const std::wstring& feature, const std::wstring& detail) {
        std::string msg = "DETECTION|" + WToUtf8(feature) + "|" + WToUtf8(detail);
        SendRaw(msg);
    }

    void SendInfo(const std::wstring& tag, const std::wstring& detail) {
        std::string msg = "INFO|" + WToUtf8(tag) + "|" + WToUtf8(detail);
        SendRaw(msg);
    }
}
}
