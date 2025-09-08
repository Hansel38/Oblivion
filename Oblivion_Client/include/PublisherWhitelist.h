#pragma once
#include <string>
#include <vector>

namespace OblivionEye {
    namespace PublisherWhitelist {
        // Tambah publisher terpercaya (CN) dalam lowercase, misal: "microsoft corporation"
        void AddTrusted(const std::wstring& publisherNameLower);
        // Daftar publisher terpercaya saat ini
        const std::vector<std::wstring>& GetTrusted();
        // Mengambil CN subject dari file yang signed. Return true jika berhasil dan signed.
        bool GetFilePublisherCN(const std::wstring& filePath, std::wstring& outPublisherCN);
        // Return true jika file signed dan subject ada dalam whitelist.
        bool IsFileSignedByTrusted(const std::wstring& filePath);
    }
}
