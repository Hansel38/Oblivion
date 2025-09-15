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
    SendRaw(OblivionEye::StringUtil::WideToUtf8(OblivionEye::LogTags::DETECTION) + "|" + WToUtf8(feature) + "|" + WToUtf8(detail));
}

void SendInfo(const std::wstring &tag, const std::wstring &detail) {
    RuntimeStats::Instance().IncInfo();
    if (tag == L"Heartbeat") RuntimeStats::Instance().IncHeartbeat();
    SendRaw(OblivionEye::StringUtil::WideToUtf8(OblivionEye::LogTags::INFO) + "|" + OblivionEye::StringUtil::WideToUtf8(tag) + "|" + OblivionEye::StringUtil::WideToUtf8(detail));
}
}
}
