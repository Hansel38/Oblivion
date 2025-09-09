#pragma once
#include <string>

namespace OblivionEye {
    struct SignatureInfo {
        bool trusted = false;             // true jika verifikasi chain + (opsional revocation) sukses
        std::wstring publisherCN;         // CN publisher (jika ada)
        bool fromCache = false;           // true jika hasil diambil dari cache
    };

    // Verifikasi tanda tangan digital dengan chain validation.
    // Jika revocationOnline = true, akan mencoba cek revocation penuh (lebih lambat, bisa akses network jika allowed).
    // Jika false, menggunakan cache-only retrieval (offline) agar lebih cepat.
    SignatureInfo VerifyFileSignatureExtended(const std::wstring& path, bool revocationOnline = false);
    // Membersihkan cache (opsional, untuk pengujian / hot reload daftar file)
    void ClearSignatureCache();
}
