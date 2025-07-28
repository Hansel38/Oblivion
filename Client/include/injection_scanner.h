#pragma once
#include <string>

namespace InjectionScanner {
    bool DetectInjectedModules();
    bool IsModuleWhitelisted(const std::wstring& moduleName);
}