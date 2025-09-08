#include "../pch.h"
#include "../include/Signatures.h"

namespace OblivionEye {
    static std::vector<BytePattern> g_sigs = {
        // Contoh signature (kosong dulu untuk minim false positive)
        // {L"Example", {0x90,0x90,0x90}, {true,true,true}},
    };

    const std::vector<BytePattern>& GetSignatures() { return g_sigs; }
}
