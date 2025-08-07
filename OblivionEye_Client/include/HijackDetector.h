#pragma once
#include <string>
#include <vector>
#include <windows.h>

// Struktur untuk menyimpan informasi thread
struct ThreadInfo {
    DWORD threadId;
    HMODULE owningModule;
    std::string moduleName;
    uintptr_t startAddress;
};

// Deklarasi fungsi
std::vector<ThreadInfo> GetAllThreadsInProcess();
bool IsModuleKnown(HMODULE hModule);
bool DetectHijackedThreads();
void ContinuousHijackDetection();
LPVOID GetThreadStartAddress(HANDLE hThread); // TAMBAHKAN INI