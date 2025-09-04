#include "../include/MemoryScanner.h"
#include <windows.h>
#include <vector>
#include <thread>
#include <chrono>
#include <iostream>
#include "../include/Logger.h"
#include "../include/Config.h"
#include "../include/DetectionController.h"
#include "../include/SleepUtil.h"

// Fungsi untuk membandingkan data dengan pattern dan mask
bool DataCompare(const unsigned char* pData, const unsigned char* bMask, const char* szMask) {
    for (; *szMask; ++szMask, ++pData, ++bMask) if (*szMask == 'x' && *pData != *bMask) return false; return (*szMask)==0; }
uintptr_t FindPattern(uintptr_t dwAddress, uintptr_t dwLen, unsigned char* bMask, const char* szMask) {
    for (uintptr_t i=0;i<dwLen;i++) if (DataCompare((unsigned char*)(dwAddress+i), bMask, szMask)) return (uintptr_t)(dwAddress+i); return 0; }

// Fungsi untuk mendapatkan semua region memori yang dapat dibaca
std::vector<MEMORY_BASIC_INFORMATION> GetMemoryRegions(HANDLE hProcess) {
    std::vector<MEMORY_BASIC_INFORMATION> regions; MEMORY_BASIC_INFORMATION mbi; uintptr_t address = 0; while (VirtualQueryEx(hProcess,(LPCVOID)address,&mbi,sizeof(mbi))) { if (mbi.State==MEM_COMMIT) { if ((mbi.Protect & (PAGE_READONLY|PAGE_READWRITE|PAGE_EXECUTE_READ|PAGE_EXECUTE_READWRITE)) && !(mbi.Protect & (PAGE_GUARD|PAGE_NOACCESS))) regions.push_back(mbi);} address=(uintptr_t)mbi.BaseAddress + mbi.RegionSize; if (address>=0x7FFFFFFFFFFF) break;} return regions; }

// Fungsi untuk scan memori berdasarkan signature
bool ScanMemoryForSignatures() {
    auto& cfg = Config::Get(); HANDLE hProcess = GetCurrentProcess(); auto regions = GetMemoryRegions(hProcess); bool detected=false; Logger::Log(LOG_INFO, "Starting memory scan for " + std::to_string(cfg.memorySignatures.size()) + " signatures...");
    for (const auto& sig : cfg.memorySignatures) {
        if (DetectionController::IsStopRequested()) break;
        if (sig.pattern.empty() || sig.mask.empty()) continue; if (sig.pattern.size()!=sig.mask.size()) { Logger::Log(LOG_WARNING, "Signature size/mask mismatch: " + sig.name); continue; }
        Logger::Log(LOG_INFO, "Scanning for signature: " + sig.name);
        for (const auto& region : regions) {
            if (DetectionController::IsStopRequested()) break;
            if (region.RegionSize < sig.pattern.size()) continue; const SIZE_T MAX_REGION = 64*1024*1024; SIZE_T toRead = region.RegionSize; if (toRead > MAX_REGION) continue; std::vector<unsigned char> buffer; buffer.resize(toRead); SIZE_T bytesRead=0; if (ReadProcessMemory(hProcess, region.BaseAddress, buffer.data(), toRead, &bytesRead)) { if (bytesRead < sig.pattern.size()) continue; uintptr_t searchLen = (uintptr_t)(bytesRead - sig.pattern.size() + 1); uintptr_t foundAddr = FindPattern((uintptr_t)buffer.data(), searchLen, (unsigned char*)sig.pattern.data(), sig.mask.c_str()); if (foundAddr) { uintptr_t realAddr = (uintptr_t)region.BaseAddress + (foundAddr - (uintptr_t)buffer.data()); Logger::Log(LOG_DETECTED, "Signature '" + sig.name + "' detected at address: 0x" + std::to_string(realAddr)); detected=true; } } }
    }
    Logger::Log(LOG_INFO, "Memory scan completed."); return detected; }

// Fungsi untuk scanning continuous
void ContinuousMemoryScan() {
    auto& cfg = Config::Get(); Logger::Log(LOG_INFO, "Memory Signature Scanner started"); SleepWithStopSeconds(cfg.memoryInitialDelaySec); if (DetectionController::IsStopRequested()) return; if (ScanMemoryForSignatures()) { DetectionController::ReportDetection("Memory signature detected at startup"); return; } while (!DetectionController::IsStopRequested()) { SleepWithStopSeconds(cfg.memoryIntervalSec); if (DetectionController::IsStopRequested()) break; if (ScanMemoryForSignatures()) { DetectionController::ReportDetection("Memory signature detected during runtime"); break; } } Logger::Log(LOG_INFO, "Memory Signature Scanner thread exiting"); }