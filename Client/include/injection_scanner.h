#pragma once
#include <string>

namespace InjectionScanner {
    bool DetectInjectedModules();
    bool IsModuleWhitelisted(const std::wstring& moduleName, const std::wstring& modulePath);
    bool IsKnownGameModule(const std::wstring& moduleName);
    bool IsSystemModule(const std::wstring& modulePath);
    bool IsSecuritySoftwareModule(const std::wstring& moduleName, const std::wstring& modulePath);
    bool IsLegitimateOverlayModule(const std::wstring& moduleName);
}