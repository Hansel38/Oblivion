#pragma once
#include <set>
#include <string>
#include <mutex>
#include <vector>
#include <utility>

namespace OblivionEye {
    namespace IntegrityChunkWhitelist {
        // Tambah chunk index ke whitelist untuk module (moduleName lowercase, misal: ntdll.dll)
    void Add(const std::wstring& moduleNameLower, size_t chunkIndex); // single
    void AddRange(const std::wstring& moduleNameLower, size_t startInclusive, size_t endInclusive); // range
    bool IsWhitelisted(const std::wstring& moduleNameLower, size_t chunkIndex);
        void Clear();
        std::vector<std::pair<std::wstring, size_t>> GetAll();
    }
}
