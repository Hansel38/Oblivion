#pragma once
#include <string>

namespace OblivionEye {
    // Interface dasar semua detector agar dapat dijadwalkan terpusat.
    class IDetector {
    public:
        virtual ~IDetector() = default;
        // Nama unik untuk logging.
        virtual const wchar_t* Name() const = 0;
        // Interval default eksekusi (ms).
        virtual unsigned IntervalMs() const = 0;
        // Aksi scan satu tick. Jangan sleep di sini.
        virtual void Tick() = 0;
    };
}
