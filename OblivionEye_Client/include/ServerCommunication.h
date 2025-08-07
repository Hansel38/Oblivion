#pragma once
#include <string>

// Fungsi untuk menghubungi server dan melakukan validasi HWID
// Mengembalikan true jika divalidasi, false jika tidak atau error.
bool PerformServerValidation(const std::string& hwid);

// Fungsi untuk mengirim laporan deteksi ke server (opsional, untuk fitur masa depan)
// void SendDetectionReport(const std::string& reportData);