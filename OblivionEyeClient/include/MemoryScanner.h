#pragma once

class MemoryScanner {
public:
    static bool IsMemoryTampered();
private:
    static bool ScanRWXMemory();
    static bool ScanHighEntropy();
    static bool CheckIATIntegrity();
    static bool ScanInlineHooks();

    // Helper
    static double CalculateEntropy(const unsigned char* data, size_t size);
};