// Reference telemetry server (plaintext + HMAC-SHA256 verifikasi)
// Build (Win): cl /EHsc TelemetryServer.cpp /Fe:TelemetryServer.exe ws2_32.lib bcrypt.lib
// NOTE: TLS belum diimplement di sample ini. Integrasikan Schannel / OpenSSL untuk produksi.

#include <winsock2.h>
#include <ws2tcpip.h>
#include <cstdio>
#include <string>
#include <vector>
#include <iostream>
#include <chrono>
#include <map>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

#pragma comment(lib, "ws2_32.lib")

static std::string HmacSha256(const std::string &key, const std::string &data){
    BCRYPT_ALG_HANDLE hAlg=nullptr; BCRYPT_HASH_HANDLE hHash=nullptr; NTSTATUS st;
    if((st=BCryptOpenAlgorithmProvider(&hAlg,BCRYPT_SHA256_ALGORITHM,nullptr,BCRYPT_ALG_HANDLE_HMAC_FLAG))!=0) return {};
    DWORD objLen=0, cb=0, hashLen=0; unsigned char *obj=nullptr; unsigned char hash[32];
    st=BCryptGetProperty(hAlg,BCRYPT_OBJECT_LENGTH,(PUCHAR)&objLen,sizeof(objLen),&cb,0); if(st!=0){ BCryptCloseAlgorithmProvider(hAlg,0); return {}; }
    st=BCryptGetProperty(hAlg,BCRYPT_HASH_LENGTH,(PUCHAR)&hashLen,sizeof(hashLen),&cb,0); if(st!=0||hashLen!=32){ BCryptCloseAlgorithmProvider(hAlg,0); return {}; }
    obj=(unsigned char*)HeapAlloc(GetProcessHeap(),0,objLen); if(!obj){ BCryptCloseAlgorithmProvider(hAlg,0); return {}; }
    st=BCryptCreateHash(hAlg,&hHash,obj,objLen,(PUCHAR)key.data(),(ULONG)key.size(),0);
    if(st==0) st=BCryptHashData(hHash,(PUCHAR)data.data(),(ULONG)data.size(),0);
    if(st==0) st=BCryptFinishHash(hHash,hash,32,0);
    if(hHash) BCryptDestroyHash(hHash); if(hAlg) BCryptCloseAlgorithmProvider(hAlg,0); if(obj) HeapFree(GetProcessHeap(),0,obj);
    if(st!=0) return {};
    static const char* hx="0123456789abcdef"; std::string out; out.resize(64);
    for(int i=0;i<32;++i){ out[i*2]=hx[(hash[i]>>4)&0xF]; out[i*2+1]=hx[hash[i]&0xF]; }
    return out;
}

struct SessInfo { unsigned long long lastSeq=0; unsigned drops=0; };
static std::map<std::string,SessInfo> g_sessions;

static bool ValidateHmacFrame(const std::string &line, const std::string &keyUtf8, std::string &sidOut, unsigned long long &seqOut, std::string &algOut){
    // Format: INTSTAT|sid=<hex32>|seq=<n>|{json...}|X=<hmac>|ALG=...
    if(line.rfind("INTSTAT|",0)!=0) return false;
    size_t off = 8; // after INTSTAT|
    // sid=
    auto sidPos = line.find("sid=", off); if(sidPos!=8) return false; size_t bar = line.find('|', sidPos); if(bar==std::string::npos) return false; sidOut = line.substr(sidPos+4, bar-(sidPos+4));
    auto seqPos = bar+1; if(line.compare(seqPos,4,"seq=")!=0) return false; size_t bar2 = line.find('|', seqPos); if(bar2==std::string::npos) return false; seqOut = std::strtoull(line.c_str()+seqPos+4,nullptr,10);
    // Find |X=
    auto xPos = line.rfind("|X="); if(xPos==std::string::npos) return false; // require
    auto algPos = line.rfind("|ALG="); if(algPos==std::string::npos || algPos < xPos) return false;
    std::string supplied = line.substr(xPos+3, algPos-(xPos+3));
    algOut = line.substr(algPos+5);
    std::string core = line.substr(0,xPos); // HMAC dihitung atas payload sebelum |X=
    auto hmac = HmacSha256(keyUtf8, core);
    return !hmac.empty() && _stricmp(hmac.c_str(), supplied.c_str())==0;
}

int main(int argc, char** argv){
    if(argc < 3){
        std::fprintf(stderr, "Usage: %s <listen_ip> <port> [key]\n", argv[0]);
        return 1;
    }
    std::string ip = argv[1];
    unsigned short port = (unsigned short)std::stoi(argv[2]);
    std::string key = (argc>=4)? argv[3] : "OBLIVION_DEFAULT_KEY";

    WSADATA wsa; WSAStartup(MAKEWORD(2,2), &wsa);
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(s==INVALID_SOCKET){ std::perror("socket"); return 2; }
    sockaddr_in addr{}; addr.sin_family=AF_INET; addr.sin_port=htons(port); inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);
    if(bind(s,(sockaddr*)&addr,sizeof(addr))==SOCKET_ERROR){ std::perror("bind"); return 3; }
    listen(s, 4);
    std::printf("Telemetry server listening on %s:%u\n", ip.c_str(), port);

    for(;;){
        SOCKET c = accept(s,nullptr,nullptr); if(c==INVALID_SOCKET) continue;
        std::printf("Client connected\n");
        std::string buffer; buffer.reserve(8192);
        char tmp[1024];
        for(;;){
            int r = recv(c,tmp,sizeof(tmp),0);
            if(r<=0) break;
            buffer.append(tmp,r);
            size_t pos;
            while((pos = buffer.find('\n')) != std::string::npos){
                std::string line = buffer.substr(0,pos);
                buffer.erase(0,pos+1);
                if(line.rfind("INTSTAT|",0)==0){
                    std::string sid, alg; unsigned long long seq=0; bool ok = ValidateHmacFrame(line,key,sid,seq,alg);
                    auto &si = g_sessions[sid];
                    bool orderOk = (seq==0) || (seq > si.lastSeq);
                    if(orderOk) si.lastSeq = seq; else si.drops++;
                    std::printf("sid=%s seq=%llu hmac=%s alg=%s order=%s drops=%u raw=%s\n",
                        sid.c_str(), seq, ok?"OK":"FAIL", alg.c_str(), orderOk?"OK":"OUT", si.drops, line.c_str());
                } else {
                    std::printf("OTHER: %s\n", line.c_str());
                }
            }
        }
        closesocket(c);
        std::printf("Client disconnected\n");
    }
    closesocket(s);
    WSACleanup();
    return 0;
}
