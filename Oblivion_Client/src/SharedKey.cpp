#include "../pch.h"
#include "../include/SharedKey.h"
#include "../include/Config.h"
#include "../include/StringUtil.h"
#include <mutex>

namespace OblivionEye {
    SharedKeyManager& SharedKeyManager::Instance() { static SharedKeyManager s; return s; }
    SharedKeyManager::SharedKeyManager() {
        m_keyUtf8 = StringUtil::WideToUtf8(Config::PIPE_SHARED_KEY);
    }
    std::string SharedKeyManager::GetUtf8() {
        std::lock_guard<std::mutex> lk(m_mtx);
        return m_keyUtf8;
    }
    void SharedKeyManager::SetFromUtf8(const std::string& utf8) {
        if (utf8.empty()) return;
        std::lock_guard<std::mutex> lk(m_mtx);
        m_keyUtf8 = utf8;
    }
}
