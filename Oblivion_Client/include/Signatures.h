#pragma once
#include <vector>
#include <string>
#include <cstdint>

namespace OblivionEye {
    struct BytePattern {
        std::wstring name; // nama signature untuk pelaporan
        std::vector<uint8_t> bytes; // nilai byte (0 jika wildcard)
        std::vector<bool> mask;     // true = compare, false = wildcard
    };

    // Mengembalikan daftar signature yang akan discan di memory proses.
    // Catatan: default kosong untuk hindari false positive. Tambahkan secara bertahap.
    const std::vector<BytePattern>& GetSignatures();
}
