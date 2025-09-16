#include "../pch.h"
#include "../include/EventReporter.h"
#include "../include/PipeClient.h"
#include "../include/RuntimeStats.h"
#include "../include/LogTags.h"
#include <string>
#include "../include/StringUtil.h"

namespace OblivionEye {
namespace EventReporter {
namespace {
    std::string WToUtf8(const std::wstring &w) {
        return OblivionEye::StringUtil::WideToUtf8(w);
    }
}

void SendRaw(const std::string &line) {
    if (!PipeClient::Instance().IsRunning()) return;
    PipeClient::Instance().Send(line + "\n");
}

void SendDetection(const std::wstring &feature, const std::wstring &detail) {
    RuntimeStats::Instance().IncDetection();
    auto feat = Sanitize(WToUtf8(feature));
    auto det  = Sanitize(WToUtf8(detail));
    SendRaw(OblivionEye::StringUtil::WideToUtf8(OblivionEye::LogTags::DETECTION) + "|" + feat + "|" + det);
}

void SendInfo(const std::wstring &tag, const std::wstring &detail) {
    RuntimeStats::Instance().IncInfo();
    if (tag == L"Heartbeat") RuntimeStats::Instance().IncHeartbeat();
    auto t = Sanitize(WToUtf8(tag));
    auto d = Sanitize(WToUtf8(detail));
    SendRaw(OblivionEye::StringUtil::WideToUtf8(OblivionEye::LogTags::INFO) + "|" + t + "|" + d);
}

std::string Sanitize(const std::string &s) {
    std::string out; out.reserve(s.size());
    for(char c : s) {
        switch(c) {
            case '\n': case '\r': out.push_back(' '); break; // normalize newlines
            case '|': out.append("\\u007C"); break;          // escape delimiter
            default:
                // control chars below 0x20 -> space
                if (static_cast<unsigned char>(c) < 0x20) out.push_back(' '); else out.push_back(c);
        }
    }
    return out;
}
}
}
