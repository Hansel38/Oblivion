#pragma once
#include <Windows.h>
#include <string>

namespace MemoryScanner {
    bool ScanMemoryForSignatures();
    bool ScanRegionForSignature(const BYTE* startAddress, SIZE_T regionSize, const BYTE* signature, const char* mask, SIZE_T signatureLength);
    void AddToWhitelist(BYTE* baseAddress, SIZE_T regionSize);
}