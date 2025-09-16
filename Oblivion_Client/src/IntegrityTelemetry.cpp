#include "../pch.h"
#include "../include/IntegrityTelemetry.h"
#include <iomanip>
#include <sstream>

namespace OblivionEye {

IntegrityTelemetry& IntegrityTelemetry::Instance() { static IntegrityTelemetry s; return s; }

std::wstring IntegrityTelemetry::NowIso() const {
    using namespace std::chrono;
    auto now = system_clock::now();
    std::time_t tt = system_clock::to_time_t(now);
    std::tm tm{};
    gmtime_s(&tm, &tt);
    std::wstringstream ss; ss<<std::put_time(&tm, L"%Y-%m-%dT%H:%M:%SZ");
    return ss.str();
}

IntegrityModuleStats IntegrityTelemetry::Get(const std::wstring& module) {
    std::lock_guard<std::mutex> lg(m_mtx);
    return m_stats[module];
}

void IntegrityTelemetry::Update(const std::wstring& module, const IntegrityModuleStats& stats) {
    std::lock_guard<std::mutex> lg(m_mtx);
    m_stats[module] = stats;
}

IntegrityModuleStats& IntegrityTelemetry::Ref(const std::wstring& module) {
    std::lock_guard<std::mutex> lg(m_mtx);
    return m_stats[module];
}

}
