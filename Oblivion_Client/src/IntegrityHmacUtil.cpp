#include "../pch.h"
#include "../include/IntegrityHmacUtil.h"
#include "../include/Config.h"
#include "../include/HWID.h"
#include "../include/HashUtil.h"
#include <cstring>
#include <algorithm>
#include <cctype>
#include <cwctype>

namespace OblivionEye { namespace IntegrityHmacUtil {

void BuildModuleKey(const wchar_t* moduleName, std::vector<unsigned char>& outKey, bool mixHwid) {
    if(!moduleName || !*moduleName) moduleName = L"unknown";
    static const unsigned char p1[8] = {0x51,0xA2,0xF3,0x14,0x25,0xD6,0xE7,0x38};
    static const unsigned char p2[8] = {0x99,0x28,0xB7,0x4E,0x5D,0xC4,0x73,0x1A};
    static const unsigned char p3[8] = {0x0F,0xEE,0xAD,0x7C,0x6B,0x5A,0x49,0x38};
    static const unsigned char p4[8] = {0xD1,0xC2,0xB3,0xA4,0x95,0x86,0x77,0x68};
    outKey.resize(32);
    for(int i=0;i<8;++i)  outKey[i]      = static_cast<unsigned char>((p1[i] ^ 0x5Au) + (i*11));
    for(int i=0;i<8;++i)  outKey[8+i]    = static_cast<unsigned char>((p2[i] ^ 0xA5u) + (i*7));
    for(int i=0;i<8;++i)  outKey[16+i]   = static_cast<unsigned char>((p3[i] ^ 0x3Cu) + (i*5));
    for(int i=0;i<8;++i)  outKey[24+i]   = static_cast<unsigned char>((p4[i] ^ 0xC3u) + (i*13));
    for(size_t i=0;i<outKey.size(); ++i) {
        unsigned char rot = static_cast<unsigned char>(((outKey[i] << (i%5)) | (outKey[i] >> (8-(i%5)))) & 0xFF);
        outKey[i] = rot ^ static_cast<unsigned char>(0xAA ^ (i*17));
    }
    if(mixHwid) {
        std::wstring hwid = GenerateHWID();
        if(!hwid.empty()) {
            for(size_t i=0;i<outKey.size(); ++i) {
                wchar_t c = hwid[i % hwid.size()];
                outKey[i] ^= static_cast<unsigned char>((c & 0xFF) ^ ((c>>8)&0x0F));
                outKey[i] = static_cast<unsigned char>((outKey[i] + (i*29)) ^ 0x5F);
            }
        }
    }
    std::wstring mod = moduleName;
    std::transform(mod.begin(), mod.end(), mod.begin(), [](wchar_t c){ return (wchar_t)::towlower(c); });
    const std::wstring dllL = L".dll";
    if(mod.size() > dllL.size()) {
        if(mod.substr(mod.size()-dllL.size()) == dllL) mod.erase(mod.size()-dllL.size());
    }
    for(size_t i=0;i<outKey.size(); ++i) {
        wchar_t c = mod[i % mod.size()];
        outKey[i] ^= static_cast<unsigned char>((c * 131) ^ (i * 37));
        outKey[i] = static_cast<unsigned char>((outKey[i] << 1) | (outKey[i] >> 7));
    }
}

bool HmacSha256(const unsigned char* key, size_t keyLen, const unsigned char* data, size_t dataLen, unsigned char out[32]) {
    if(!key || !data || !out) return false;
    const size_t BLK = 64;
    unsigned char kh[32];
    const unsigned char* kUse = key; size_t kUseLen = keyLen;
    if(keyLen > BLK) {
        if(!HashUtil::Sha256(key, keyLen, kh)) return false;
        kUse = kh; kUseLen = 32;
    }
    unsigned char ipad[BLK]; unsigned char opad[BLK];
    memset(ipad,0,BLK); memset(opad,0,BLK);
    memcpy(ipad,kUse,kUseLen); memcpy(opad,kUse,kUseLen);
    for(size_t i=0;i<BLK;++i){ ipad[i]^=0x36; opad[i]^=0x5c; }
    std::vector<unsigned char> buf; buf.reserve(BLK + dataLen);
    buf.insert(buf.end(), ipad, ipad+BLK);
    if(dataLen) buf.insert(buf.end(), data, data+dataLen);
    unsigned char inner[32]; if(!HashUtil::Sha256(buf.data(), buf.size(), inner)) return false;
    std::vector<unsigned char> obuf; obuf.reserve(BLK + 32);
    obuf.insert(obuf.end(), opad, opad+BLK);
    obuf.insert(obuf.end(), inner, inner+32);
    if(!HashUtil::Sha256(obuf.data(), obuf.size(), out)) return false;
    return true;
}

}}
