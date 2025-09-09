#include "../pch.h"
#include "../include/PublisherWhitelist.h"
#include <windows.h>
#include <wincrypt.h>
#include <softpub.h>
#include <vector>
#include <string>
#include <algorithm>
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

namespace OblivionEye {
namespace PublisherWhitelist {

    static std::vector<std::wstring> g_trusted;

    void AddTrusted(const std::wstring& publisherNameLower) {
        std::wstring low = publisherNameLower;
        std::transform(low.begin(), low.end(), low.begin(), ::towlower);
        g_trusted.push_back(low);
    }

    void Clear() { g_trusted.clear(); }

    const std::vector<std::wstring>& GetTrusted() { return g_trusted; }

    static std::wstring ToLowerW(const std::wstring& s) {
        std::wstring r = s;
        std::transform(r.begin(), r.end(), r.begin(), ::towlower);
        return r;
    }

    bool GetFilePublisherCN(const std::wstring& filePath, std::wstring& outPublisherCN) {
        outPublisherCN.clear();
        HCERTSTORE hStore = nullptr; 
        HCRYPTMSG hMsg = nullptr; 
        PCCERT_CONTEXT pCertContext = nullptr;
        PCMSG_SIGNER_INFO pSignerInfo = nullptr;

        BOOL ok = CryptQueryObject(CERT_QUERY_OBJECT_FILE, filePath.c_str(),
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, CERT_QUERY_FORMAT_FLAG_BINARY, 0,
            nullptr, nullptr, nullptr, &hStore, &hMsg, nullptr);
        if (!ok) {
            return false;
        }

        DWORD dwSignerInfo = 0;
        if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &dwSignerInfo)) {
            CryptMsgClose(hMsg);
            CertCloseStore(hStore, 0);
            return false;
        }
        pSignerInfo = (PCMSG_SIGNER_INFO)LocalAlloc(LPTR, dwSignerInfo);
        if (!pSignerInfo) {
            CryptMsgClose(hMsg);
            CertCloseStore(hStore, 0);
            return false;
        }
        if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, pSignerInfo, &dwSignerInfo)) {
            LocalFree(pSignerInfo);
            CryptMsgClose(hMsg);
            CertCloseStore(hStore, 0);
            return false;
        }

        CERT_INFO ci; ZeroMemory(&ci, sizeof(ci));
        ci.Issuer = pSignerInfo->Issuer; 
        ci.SerialNumber = pSignerInfo->SerialNumber;
        pCertContext = CertFindCertificateInStore(hStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            0, CERT_FIND_SUBJECT_CERT, (PVOID)&ci, nullptr);
        if (!pCertContext) {
            LocalFree(pSignerInfo);
            CryptMsgClose(hMsg);
            CertCloseStore(hStore, 0);
            return false;
        }

        DWORD len = CertGetNameStringW(pCertContext, CERT_NAME_ATTR_TYPE, 0, const_cast<void*>((const void*)szOID_COMMON_NAME), nullptr, 0);
        if (len > 1) {
            std::wstring cn; cn.resize(len);
            CertGetNameStringW(pCertContext, CERT_NAME_ATTR_TYPE, 0, const_cast<void*>((const void*)szOID_COMMON_NAME), &cn[0], len);
            if (!cn.empty() && cn.back() == L'\0') cn.pop_back();
            outPublisherCN = cn;
        }

        // cleanup
        CertFreeCertificateContext(pCertContext);
        LocalFree(pSignerInfo);
        CryptMsgClose(hMsg);
        CertCloseStore(hStore, 0);
        return !outPublisherCN.empty();
    }

    bool IsFileSignedByTrusted(const std::wstring& filePath) {
        std::wstring cn;
        if (!GetFilePublisherCN(filePath, cn)) return false;
        auto cnLower = ToLowerW(cn);
        for (const auto& t : g_trusted) if (cnLower == t) return true; return false;
    }
}
}
