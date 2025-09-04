#pragma once
#include <string>

// Persistent connection to anti-cheat server
// PerformServerValidation sekarang: connect + VALIDATE_HWID dan menjaga socket tetap hidup
// Mengembalikan true jika validasi sukses & koneksi dipertahankan.
bool PerformServerValidation(const std::string& hwid);

// Shutdown koneksi persistent (dipanggil saat unload / detach)
void ShutdownServerSession();

// Status helper
bool IsServerSessionAlive();