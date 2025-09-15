#include "../pch.h"
#include "../include/Signatures.h"
#include "../include/Logger.h"
#include <sstream>

namespace OblivionEye {
    static std::vector<BytePattern> g_sigs = {
                // Signature dasar Cheat Engine (aman: pattern generik speedhack shell jmp stub: E9 ?? ?? ?? ?? 90 90)
                { L"CE_Speedhack_JmpStub", {0xE9,0x00,0x00,0x00,0x00,0x90,0x90}, {true,false,false,false,false,true,true} },
                // String ASCII cluster (First Scan\0Next Scan) dalam satu blok (di-encode sebagai byte dengan wildcard pada variasi huruf besar)
                // Pola sederhana: "First Scan" + null + beberapa byte + "Next Scan"
                { L"CE_UI_FirstNextScan", { 'F','i','r','s','t',' ','S','c','a','n',0x00,0x00,0x00,'N','e','x','t',' ','S','c','a','n' },
                    { true,true,true,true,true,true,true,true,true,true,true,false,false,true,true,true,true,true,true,true,true } },
    };

    const std::vector<BytePattern>& GetSignatures() { return g_sigs; }
    void ClearSignatures() { g_sigs.clear(); }

    bool AddSignaturePattern(const std::wstring &name, const std::wstring &pattern) {
        std::wstringstream ws(pattern);
        std::wstring tok; std::vector<uint8_t> bytes; std::vector<bool> mask;
        while (ws >> tok) {
            if (tok == L"??") { bytes.push_back(0); mask.push_back(false); continue; }
            if (tok.empty() || tok.size() > 2) { Log(L"AddSignaturePattern: token invalid (size) '" + tok + L"'"); return false; }
            unsigned int val = 0;
            // Manual parse hex (avoid manipulators if not included)
            for (auto ch : tok) {
                val <<= 4;
                if (ch >= L'0' && ch <= L'9') val |= (ch - L'0');
                else if (ch >= L'a' && ch <= L'f') val |= (10 + ch - L'a');
                else if (ch >= L'A' && ch <= L'F') val |= (10 + ch - L'A');
                else { Log(L"AddSignaturePattern: token invalid char '" + std::wstring(1, ch) + L"'"); return false; }
            }
            bytes.push_back(static_cast<uint8_t>(val & 0xFF));
            mask.push_back(true);
        }
        if (bytes.empty()) { Log(L"AddSignaturePattern: pattern kosong untuk '" + name + L"'"); return false; }
        g_sigs.push_back(BytePattern{ name, std::move(bytes), std::move(mask) });
        return true;
    }
}
