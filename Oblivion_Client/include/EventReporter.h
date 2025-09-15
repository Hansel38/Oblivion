#pragma once
#include <string>

namespace OblivionEye {
namespace EventReporter {
    void SendRaw(const std::string &line);
    void SendDetection(const std::wstring &feature, const std::wstring &detail);
    void SendInfo(const std::wstring &tag, const std::wstring &detail);
}
}
