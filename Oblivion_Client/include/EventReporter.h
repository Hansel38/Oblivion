#pragma once
#include <string>

namespace OblivionEye {
namespace EventReporter {
    void SendRaw(const std::string &line);
    void SendDetection(const std::wstring &feature, const std::wstring &detail);
    void SendInfo(const std::wstring &tag, const std::wstring &detail);
    // Sanitize a UTF-8 segment for pipe transmission: replace '\n' and '\r' with space,
    // escape '|' delimiter by replacing it with "\u007C" (printable fallback) to avoid
    // shifting field boundaries. Exposed for unit tests.
    std::string Sanitize(const std::string &s);
}
}
