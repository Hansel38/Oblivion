#pragma once

namespace OblivionEye {
    // Proteksi basic anti hijack: drop SeDebugPrivilege, enable mitigasi, dan perketat DACL process
    class HandleProtection {
    public:
        static void Apply();
    };
}
