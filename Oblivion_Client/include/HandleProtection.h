#pragma once

namespace OblivionEye {
    // Proteksi basic: drop SeDebugPrivilege, perketat DACL + deteksi handle intrusif eksternal.
    // Kini bertindak sebagai detector (punya Tick) untuk memeriksa proses lain yang memegang handle
    // ke proses game dengan akses WRITE / VM / DEBUG. Fokus memicu detection sebelum injeksi memory.
    class HandleProtection {
    public:
        static void Apply();
        static void Tick();
    private:
        static bool ScanOnce();
    };
}
