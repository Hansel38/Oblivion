#include "../pch.h"
#include "../include/IATHookChecker.h"
#include "../include/Logger.h"
#include "../include/Utils.h"
#include "../include/EventReporter.h"
#include <windows.h>
#include <psapi.h>
#include <imagehlp.h>
#include <thread>
#include <chrono>

#pragma comment(lib, "imagehlp.lib")

namespace OblivionEye {

    IATHookChecker& IATHookChecker::Instance() { static IATHookChecker s; return s; }

    static PIMAGE_NT_HEADERS GetNtHeaders(BYTE* base) {
        auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
        if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
        auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(base + dos->e_lfanew);
        if (!nt || nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;
        return nt;
    }

    static bool IsAddressInsideModule(HMODULE mod, void* addr) {
        MODULEINFO mi{};
        if (!GetModuleInformation(GetCurrentProcess(), mod, &mi, sizeof(mi))) return false;
        auto base = reinterpret_cast<uint8_t*>(mi.lpBaseOfDll);
        size_t size = mi.SizeOfImage;
        auto p = reinterpret_cast<uint8_t*>(addr);
        return p >= base && p < base + size;
    }

    bool IATHookChecker::ScanModuleIAT(HMODULE hMod) {
        MODULEINFO mi{};
        if (!GetModuleInformation(GetCurrentProcess(), hMod, &mi, sizeof(mi))) return false;
        BYTE* base = reinterpret_cast<BYTE*>(mi.lpBaseOfDll);
        auto nt = GetNtHeaders(base);
        if (!nt) return false;
        auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (!dir.VirtualAddress || !dir.Size) return false;
        auto impDesc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(base + dir.VirtualAddress);
        for (; impDesc->Name; ++impDesc) {
            auto oft = reinterpret_cast<PIMAGE_THUNK_DATA>(base + impDesc->OriginalFirstThunk);
            auto ft = reinterpret_cast<PIMAGE_THUNK_DATA>(base + impDesc->FirstThunk);
            if (!oft || !ft) continue;
            for (; oft->u1.AddressOfData; ++oft, ++ft) {
#ifdef _WIN64
                if (!(oft->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                    void* target = reinterpret_cast<void*>(ft->u1.Function);
                    HMODULE owner = nullptr;
                    GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                        static_cast<LPCWSTR>(target), &owner);
                    if (owner && !IsAddressInsideModule(owner, target)) {
                        EventReporter::SendDetection(L"IATHookChecker", L"IAT hook");
                        ShowDetectionAndExit(L"IAT hook terdeteksi");
                        return true;
                    }
                }
#else
                if (!(oft->u1.Ordinal & IMAGE_ORDINAL_FLAG32)) {
                    void* target = reinterpret_cast<void*>(ft->u1.Function);
                    HMODULE owner = nullptr;
                    GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                        reinterpret_cast<LPCSTR>(target), &owner);
                    if (owner && !IsAddressInsideModule(owner, target)) {
                        EventReporter::SendDetection(L"IATHookChecker", L"IAT hook");
                        ShowDetectionAndExit(L"IAT hook terdeteksi");
                        return true;
                    }
                }
#endif
            }
        }
        return false;
    }

    bool IATHookChecker::ScanIAT() {
        HMODULE mods[1024] = {};
        DWORD needed = 0;
        if (!EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &needed)) return false;
        int count = needed / sizeof(HMODULE);
        for (int i = 0; i < count; ++i) {
            if (ScanModuleIAT(mods[i])) return true;
        }
        return false;
    }

    void IATHookChecker::Start(unsigned intervalMs) {
        if (m_running.exchange(true)) return;
        std::thread([this, intervalMs]() { Loop(intervalMs); }).detach();
    }

    void IATHookChecker::Stop() { m_running = false; }

    void IATHookChecker::Loop(unsigned intervalMs) {
        Log(L"IATHookChecker start");
        while (m_running) {
            if (ScanIAT()) return;
            std::this_thread::sleep_for(std::chrono::milliseconds(intervalMs));
        }
        Log(L"IATHookChecker stop");
    }
}
