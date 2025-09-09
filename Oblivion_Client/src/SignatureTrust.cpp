#include "../pch.h"
#include "../include/SignatureTrust.h"
#include <windows.h>
#include <wincrypt.h>
#include <softpub.h>
#include <map>
#include <mutex>
#include <string>
#include <algorithm>
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

namespace OblivionEye {

    static std::mutex g_sigCacheMtx;
    static std::map<std::wstring, SignatureInfo> g_sigCache; // path -> info

    static std::wstring ToLowerW(const std::wstring& s) {
        std::wstring r = s; std::transform(r.begin(), r.end(), r.begin(), ::towlower); return r;
    }

    void ClearSignatureCache() {
        std::lock_guard<std::mutex> lk(g_sigCacheMtx);
        g_sigCache.clear();
    }

    SignatureInfo VerifyFileSignatureExtended(const std::wstring& path, bool revocationOnline) {
        {
            std::lock_guard<std::mutex> lk(g_sigCacheMtx);
            auto it = g_sigCache.find(path);
            if (it != g_sigCache.end()) {
                SignatureInfo cached = it->second; cached.fromCache = true; return cached;
            }
        }

        SignatureInfo result; // default false
        WINTRUST_FILE_INFO fileInfo{}; fileInfo.cbStruct = sizeof(fileInfo); fileInfo.pcwszFilePath = path.c_str();
        GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        WINTRUST_DATA wtd{}; wtd.cbStruct = sizeof(wtd);
        wtd.dwUIChoice = WTD_UI_NONE;
        wtd.fdwRevocationChecks = revocationOnline ? WTD_REVOKE_WHOLECHAIN : WTD_REVOKE_NONE;
        wtd.dwUnionChoice = WTD_CHOICE_FILE; wtd.pFile = &fileInfo;
        wtd.dwProvFlags = (revocationOnline ? 0 : (WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE));
        wtd.dwStateAction = WTD_STATEACTION_VERIFY;

        LONG status = WinVerifyTrust(nullptr, &policyGUID, &wtd);
        // Cleanup state handle
        wtd.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(nullptr, &policyGUID, &wtd);

        if (status == ERROR_SUCCESS) {
            result.trusted = true;
            // Extract publisher CN using CryptQueryObject similar to existing minimal approach
            HCERTSTORE hStore = nullptr; HCRYPTMSG hMsg = nullptr; PCCERT_CONTEXT pCert = nullptr; PCMSG_SIGNER_INFO pInfo = nullptr;
            if (CryptQueryObject(CERT_QUERY_OBJECT_FILE, path.c_str(),
                CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, CERT_QUERY_FORMAT_FLAG_BINARY, 0,
                nullptr, nullptr, nullptr, &hStore, &hMsg, nullptr)) {
                DWORD sz = 0;
                if (CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &sz)) {
                    pInfo = (PCMSG_SIGNER_INFO)LocalAlloc(LPTR, sz);
                    if (pInfo && CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, pInfo, &sz)) {
                        CERT_INFO ci{}; ci.Issuer = pInfo->Issuer; ci.SerialNumber = pInfo->SerialNumber;
                        pCert = CertFindCertificateInStore(hStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_SUBJECT_CERT, &ci, nullptr);
                        if (pCert) {
                            DWORD len = CertGetNameStringW(pCert, CERT_NAME_ATTR_TYPE, 0, (void*)szOID_COMMON_NAME, nullptr, 0);
                            if (len > 1) {
                                std::wstring cn; cn.resize(len);
                                CertGetNameStringW(pCert, CERT_NAME_ATTR_TYPE, 0, (void*)szOID_COMMON_NAME, &cn[0], len);
                                if (!cn.empty() && cn.back() == L'\0') cn.pop_back();
                                result.publisherCN = cn;
                            }
                        }
                    }
                }
            }
            if (pCert) CertFreeCertificateContext(pCert);
            if (pInfo) LocalFree(pInfo);
            if (hStore) CertCloseStore(hStore, 0);
            if (hMsg) CryptMsgClose(hMsg);
        }

        {
            std::lock_guard<std::mutex> lk(g_sigCacheMtx);
            g_sigCache[path] = result; // cache meskipun false (negative caching)
        }
        return result;
    }
}
