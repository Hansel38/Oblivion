#include "../pch.h"
#include "../include/HWID.h"
#include <windows.h>
#include <iphlpapi.h>
#include <wbemidl.h>
#include <comdef.h>
#include <string>
#include <vector>
#include <algorithm>
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "iphlpapi.lib")

namespace OblivionEye {

    static std::wstring GetVolumeSerial() {
        wchar_t sysDrive[MAX_PATH] = L"C:";
        DWORD serial = 0, maxComp = 0, fsFlags = 0;
        wchar_t fsName[128] = {};
        GetVolumeInformationW(sysDrive, nullptr, 0, &serial, &maxComp, &fsFlags, fsName, 128);
        wchar_t buf[32];
        swprintf_s(buf, L"%08X", serial);
        return buf;
    }

    static std::wstring GetCpuId() {
        // Basic: gunakan registry ProcessorNameString atau fallback GetSystemInfo
        HKEY h;
        wchar_t cpu[256] = {};
        DWORD sz = sizeof(cpu);
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", 0, KEY_READ, &h) == ERROR_SUCCESS) {
            if (RegQueryValueExW(h, L"ProcessorNameString", nullptr, nullptr, (LPBYTE)cpu, &sz) == ERROR_SUCCESS) {
                RegCloseKey(h);
                return cpu;
            }
            RegCloseKey(h);
        }
        SYSTEM_INFO si{}; GetSystemInfo(&si);
        wchar_t buf[64]; swprintf_s(buf, L"CPU-%u", si.dwNumberOfProcessors);
        return buf;
    }

    static std::wstring GetPrimaryMac() {
        IP_ADAPTER_INFO info[16];
        DWORD buflen = sizeof(info);
        if (GetAdaptersInfo(info, &buflen) == NO_ERROR) {
            PIP_ADAPTER_INFO p = info;
            while (p) {
                if (p->Type == MIB_IF_TYPE_ETHERNET || p->Type == IF_TYPE_IEEE80211) {
                    wchar_t mac[32];
                    swprintf_s(mac, L"%02X%02X%02X%02X%02X%02X", p->Address[0], p->Address[1], p->Address[2], p->Address[3], p->Address[4], p->Address[5]);
                    return mac;
                }
                p = p->Next;
            }
        }
        return L"000000000000";
    }

    static std::wstring HashSimple(const std::wstring& s) {
        // Hash sederhana (bukan cryptographic). Untuk basic HWID.
        uint32_t h = 2166136261u;
        for (auto c : s) {
            h ^= (uint32_t)c;
            h *= 16777619u;
        }
        wchar_t buf[32]; swprintf_s(buf, L"%08X", h);
        return buf;
    }

    std::wstring GenerateHWID() {
        std::wstring raw = GetVolumeSerial() + L"|" + GetCpuId() + L"|" + GetPrimaryMac();
        return HashSimple(raw);
    }
}
