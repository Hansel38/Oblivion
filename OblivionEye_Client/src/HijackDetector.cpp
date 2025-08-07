#include "../include/HijackDetector.h"
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h> // Untuk GetModuleFileNameEx
#include <vector>
#include <set>
#include <thread>
#include <chrono>
#include "../include/Logger.h"
#include "../include/ProcessWatcher.h" // Untuk ws2s

#pragma comment(lib, "psapi.lib")

// Set untuk menyimpan handle module yang sudah diperiksa
static std::set<HMODULE> knownModules;
static bool isModuleListInitialized = false;

// Fungsi untuk mendapatkan alamat start thread (fungsi helper) - DIPINDAHKAN KE ATAS
LPVOID GetThreadStartAddress(HANDLE hThread) {
    // Ini adalah cara yang umum, meskipun tidak 100% andal di semua Windows versi
    // Kita gunakan NtQueryInformationThread jika tersedia
    typedef NTSTATUS(NTAPI* pNtQueryInformationThread)(
        HANDLE ThreadHandle,
        ULONG ThreadInformationClass,
        PVOID ThreadInformation,
        ULONG ThreadInformationLength,
        PULONG ReturnLength
        );

    static HMODULE hNtDll = GetModuleHandleA("ntdll.dll");
    static pNtQueryInformationThread NtQueryInformationThread =
        (pNtQueryInformationThread)GetProcAddress(hNtDll, "NtQueryInformationThread");

    if (NtQueryInformationThread) {
        LPVOID startAddress = NULL;
        NTSTATUS status = NtQueryInformationThread(hThread, 9 /* ThreadQuerySetWin32StartAddress */,
            &startAddress, sizeof(startAddress), NULL);
        if (status == 0) {
            return startAddress;
        }
    }

    // Fallback: return NULL jika tidak bisa
    return NULL;
}

// Fungsi untuk mendapatkan semua module yang dimuat (dipanggil sekali)
void InitializeKnownModules(HANDLE hProcess) {
    if (isModuleListInitialized) return;

    HMODULE hMods[1024];
    DWORD cbNeeded;

    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        DWORD numMods = cbNeeded / sizeof(HMODULE);
        for (DWORD i = 0; i < numMods; i++) {
            knownModules.insert(hMods[i]);
        }
    }
    isModuleListInitialized = true;
    Logger::Log(LOG_INFO, "Initialized known modules list. Count: " + std::to_string(knownModules.size()));
}

// Fungsi untuk memeriksa apakah module dikenal
bool IsModuleKnown(HMODULE hModule) {
    return knownModules.find(hModule) != knownModules.end();
}

// Fungsi untuk mendapatkan nama module dari alamat
std::string GetModuleNameFromAddress(HANDLE hProcess, LPVOID address) {
    HMODULE hModule = NULL;
    if (GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        (LPCTSTR)address, &hModule)) {
        char moduleName[MAX_PATH];
        if (GetModuleFileNameExA(hProcess, hModule, moduleName, MAX_PATH)) {
            return std::string(moduleName);
        }
    }
    return "Unknown";
}

// Fungsi untuk mendapatkan semua thread dalam proses
std::vector<ThreadInfo> GetAllThreadsInProcess() {
    std::vector<ThreadInfo> threads;
    DWORD processId = GetCurrentProcessId();
    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

    if (hThreadSnap == INVALID_HANDLE_VALUE) {
        Logger::Log(LOG_ERROR, "Failed to create thread snapshot");
        return threads;
    }

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

    if (!Thread32First(hThreadSnap, &te32)) {
        CloseHandle(hThreadSnap);
        Logger::Log(LOG_ERROR, "Failed to get first thread");
        return threads;
    }

    HANDLE hProcess = GetCurrentProcess();
    InitializeKnownModules(hProcess); // Inisialisasi daftar module dikenal

    do {
        // Hanya thread dari proses kita sendiri
        if (te32.th32OwnerProcessID == processId) {
            ThreadInfo threadInfo;
            threadInfo.threadId = te32.th32ThreadID;

            // Buka handle thread untuk mendapatkan informasi lebih lanjut
            HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te32.th32ThreadID);
            if (hThread != NULL) {
                // Dapatkan alamat start thread
                threadInfo.startAddress = (uintptr_t)GetThreadStartAddress(hThread);

                // Dapatkan module owner dari alamat start
                HMODULE hOwningModule = NULL;
                GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                    (LPCTSTR)threadInfo.startAddress, &hOwningModule);
                threadInfo.owningModule = hOwningModule;

                // Dapatkan nama module
                if (hOwningModule != NULL) {
                    char moduleName[MAX_PATH];
                    if (GetModuleFileNameExA(hProcess, hOwningModule, moduleName, MAX_PATH)) {
                        threadInfo.moduleName = std::string(moduleName);
                    }
                    else {
                        threadInfo.moduleName = "UnknownModule";
                    }
                }
                else {
                    threadInfo.moduleName = "Unknown(NoModule)";
                }

                CloseHandle(hThread);
                threads.push_back(threadInfo);
            }
            else {
                // Jika tidak bisa buka handle, tetap catat dengan info terbatas
                threadInfo.startAddress = 0;
                threadInfo.owningModule = NULL;
                threadInfo.moduleName = "Unknown(CantOpen)";
                threads.push_back(threadInfo);
                Logger::Log(LOG_WARNING, "Cannot open thread handle for TID: " + std::to_string(te32.th32ThreadID));
            }
        }
    } while (Thread32Next(hThreadSnap, &te32));

    CloseHandle(hThreadSnap);
    return threads;
}

// Fungsi utama untuk mendeteksi thread yang dihijack
bool DetectHijackedThreads() {
    auto threads = GetAllThreadsInProcess();
    bool hijackedDetected = false;

    Logger::Log(LOG_INFO, "Scanning " + std::to_string(threads.size()) + " threads for hijacking...");

    for (const auto& thread : threads) {
        // Abaikan thread utama dan thread dari module yang dikenal
        if (IsModuleKnown(thread.owningModule)) {
            // Logger::Log(LOG_INFO, "Thread " + std::to_string(thread.threadId) + 
            //            " is from known module: " + thread.moduleName);
            continue;
        }

        // Jika thread tidak berasal dari module yang dikenal, ini mencurigakan
        Logger::Log(LOG_DETECTED, "Suspicious thread detected! TID: " + std::to_string(thread.threadId) +
            ", Module: " + thread.moduleName + ", StartAddr: 0x" + std::to_string(thread.startAddress));

        // Tandai sebagai terdeteksi
        hijackedDetected = true;

        // Untuk demo, kita tidak return true langsung agar semua thread dicatat
        // Tapi dalam produksi, bisa return true segera
        // return true;
    }

    if (!hijackedDetected) {
        Logger::Log(LOG_INFO, "No hijacked threads detected.");
    }

    return hijackedDetected;
}

// Fungsi untuk scanning continuous
void ContinuousHijackDetection() {
    Logger::Log(LOG_INFO, "Hijacked Thread Detector started");

    // Delay awal 60 detik untuk memastikan semua thread game dimuat
    std::this_thread::sleep_for(std::chrono::seconds(60));

    // Scan pertama kali saat startup
    if (DetectHijackedThreads()) {
        Logger::Log(LOG_DETECTED, "Hijacked thread detected on startup, closing client");
        ExitProcess(0);
    }

    // Scan terus-menerus setiap 90 detik
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(90));
        if (DetectHijackedThreads()) {
            Logger::Log(LOG_DETECTED, "Hijacked thread detected during runtime, closing client");
            ExitProcess(0);
        }
    }
}