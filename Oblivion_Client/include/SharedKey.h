#pragma once
#ifndef OBLIVIONEYE_SHAREDKEY_H
#define OBLIVIONEYE_SHAREDKEY_H

#include <string>
#include <mutex>

namespace OblivionEye {
    // Thread-safe manager untuk shared key handshake pipe.
    class SharedKeyManager {
    public:
        static SharedKeyManager& Instance();
        std::string GetUtf8();
        void SetFromUtf8(const std::string& utf8);
    private:
        SharedKeyManager(); // implemented in SharedKey.cpp to initialize from Config
        std::mutex m_mtx;
        std::string m_keyUtf8;
    };
}
#endif // OBLIVIONEYE_SHAREDKEY_H

