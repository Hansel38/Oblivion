#pragma once
#include <string>

class Logger {
public:
    static void Init();
    static void Log(const std::string& message);
    static void LogDetected(const std::string& processName);
    static void Close();
};