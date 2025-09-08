#pragma once
#include <string>

namespace OblivionEye {
    // Verifikasi tanda tangan digital sebuah file. Mengembalikan true jika valid/signed.
    // Catatan: Basic - hanya status signed/unsigned (tanpa detail certificate chain)
    bool VerifyFileIsSigned(const std::wstring& path);
}
