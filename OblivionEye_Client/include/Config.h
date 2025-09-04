#pragma once
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>

namespace Config {
    struct MemorySignature {
        std::string name;
        std::vector<unsigned char> pattern;
        std::string mask;
        size_t offset{};
    };

    struct Data {
        // Networking / Server
        std::string serverIp = "127.0.0.1";
        uint16_t serverPort = 8900;
        int serverTimeoutMs = 5000;
        // Crypto
        std::string encryptionKey = "OblivionEye_Secret_2025";
        // Protocol tokens
        std::string validationCommandPrefix = "VALIDATE_HWID:"; // prefix + hwid + \n
        std::string validationSuccessToken = "VALIDATION_SUCCESS";
        // Logger
        std::string logFolder = "logs";
        std::string logFileName = "oblivion_eye.log";
        std::string logStartBanner = "=== Oblivion Eye Started ===";
        std::string logStopBanner  = "=== Oblivion Eye Stopped ===";
        // Detection message prefixes
        std::string cheatDetectedPrefix = "CHEAT DETECTED:";
        std::string overlayDetectedPrefix = "Overlay/ESP hack detected:";
        // Timers / intervals (seconds unless noted)
        int antiDebugInitialDelaySec = 20;
        int antiDebugIntervalSec     = 30;
        int overlayInitialDelaySec   = 10;
        int overlayIntervalSec       = 10;
        int processInitialDelaySec   = 5;
        int processIntervalSec       = 5;
        int memoryInitialDelaySec    = 45;
        int memoryIntervalSec        = 120;
        int iatInitialDelaySec       = 90;
        int iatIntervalSec           = 180;
        int antiSuspendIntervalMs    = 500;
        // Heuristics / limits
        int windowTitleMaxLength     = 100;
        // Lists
        std::vector<std::string> blacklistedProcesses = {
            "cheatengine-x86_64.exe","cheatengine-i386.exe","openkore.exe","wpe.exe","rpe.exe",
            "ollydbg.exe","x64_dbg.exe","x32_dbg.exe","ida.exe","ida64.exe","processhacker.exe",
            "injector.exe","dllinjector.exe"
        };
        std::vector<std::string> suspiciousWindowTitles = {
            "Cheat Engine","CheatEngine","ESP Hack","Wallhack","Aimbot","TriggerBot","Memory Editor",
            "Process Hacker","x64_dbg","x32_dbg","OllyDbg","IDA Pro","IDA Freeware","Game Hack","Game Cheat",
            "RPE","WPE","WireShark","Packet Editor","DLL Injector","Speed Hack","Freeze Hack","Cheat Tool"
        };
        std::vector<std::string> overlaySafeWords = {
            "google","chrome","firefox","microsoft","edge","shopee","tokopedia","whatsapp","discord",
            "notepad","visual studio","devenv","explorer"
        };
        std::vector<std::string> systemModules = {
            "ntdll.dll","kernel32.dll","kernelbase.dll","user32.dll","gdi32.dll","advapi32.dll","shell32.dll"
        };
        // Memory signatures (demo)
        std::vector<MemorySignature> memorySignatures = {
            { "Generic_Injector_Signature", { 0x4D,0x5A,0x90,0x00,0x03,0x00,0x00,0x00,0x04,0x00,0x00,0x00 }, "xxxxxxxxxxxx", 0 }
        };
    };

    inline Data& Get() { static Data d; return d; }

    inline std::string trim(const std::string& s) {
        size_t b = s.find_first_not_of(" \t\r\n");
        size_t e = s.find_last_not_of(" \t\r\n");
        if (b == std::string::npos) return ""; return s.substr(b, e - b + 1);
    }

    // Very small key=value parser. Lists separated by comma.
    inline void Load(const std::string& path = "config.ini") {
        std::ifstream f(path);
        if (!f.is_open()) return; // keep defaults
        auto& c = Get();
        std::string line;
        while (std::getline(f, line)) {
            if (line.empty() || line[0]=='#' || line[0]==';') continue;
            auto pos = line.find('='); if (pos==std::string::npos) continue;
            std::string key = trim(line.substr(0,pos));
            std::string value = trim(line.substr(pos+1));
            if (key=="serverIp") c.serverIp = value;
            else if (key=="serverPort") c.serverPort = static_cast<uint16_t>(std::stoi(value));
            else if (key=="serverTimeoutMs") c.serverTimeoutMs = std::stoi(value);
            else if (key=="encryptionKey") c.encryptionKey = value;
            else if (key=="validationCommandPrefix") c.validationCommandPrefix = value;
            else if (key=="validationSuccessToken") c.validationSuccessToken = value;
            else if (key=="logFolder") c.logFolder = value;
            else if (key=="logFileName") c.logFileName = value;
            else if (key=="antiDebugInitialDelaySec") c.antiDebugInitialDelaySec = std::stoi(value);
            else if (key=="antiDebugIntervalSec") c.antiDebugIntervalSec = std::stoi(value);
            else if (key=="overlayInitialDelaySec") c.overlayInitialDelaySec = std::stoi(value);
            else if (key=="overlayIntervalSec") c.overlayIntervalSec = std::stoi(value);
            else if (key=="processInitialDelaySec") c.processInitialDelaySec = std::stoi(value);
            else if (key=="processIntervalSec") c.processIntervalSec = std::stoi(value);
            else if (key=="memoryInitialDelaySec") c.memoryInitialDelaySec = std::stoi(value);
            else if (key=="memoryIntervalSec") c.memoryIntervalSec = std::stoi(value);
            else if (key=="iatInitialDelaySec") c.iatInitialDelaySec = std::stoi(value);
            else if (key=="iatIntervalSec") c.iatIntervalSec = std::stoi(value);
            else if (key=="antiSuspendIntervalMs") c.antiSuspendIntervalMs = std::stoi(value);
            else if (key=="windowTitleMaxLength") c.windowTitleMaxLength = std::stoi(value);
            else if (key=="blacklistedProcesses") { c.blacklistedProcesses.clear(); std::stringstream ss(value); std::string tok; while (std::getline(ss,tok,',')) { tok=trim(tok); if(!tok.empty()) c.blacklistedProcesses.push_back(tok);} }
            else if (key=="suspiciousWindowTitles") { c.suspiciousWindowTitles.clear(); std::stringstream ss(value); std::string tok; while (std::getline(ss,tok,',')) { tok=trim(tok); if(!tok.empty()) c.suspiciousWindowTitles.push_back(tok);} }
            else if (key=="overlaySafeWords") { c.overlaySafeWords.clear(); std::stringstream ss(value); std::string tok; while (std::getline(ss,tok,',')) { tok=trim(tok); if(!tok.empty()) c.overlaySafeWords.push_back(tok);} }
        }
    }
}
