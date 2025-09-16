#pragma once
// Aggregator header untuk berbagai modul integritas.
// Tujuan: Mengurangi repetisi include antar file yang membutuhkan beberapa checker integritas.
// PERINGATAN: Gunakan bijak. Jika hanya butuh satu modul, lebih efisien include langsung header spesifik.
// Potensi trade-off: build time sedikit meningkat jika banyak file bergantung pada agregator ini.

#include "NtdllIntegrity.h"
#include "Kernel32Integrity.h"
#include "User32Integrity.h"
#include "Gdi32Integrity.h"
#include "ModuleSectionIntegrity.h"

// Jika nanti ada modul baru (misal Advapi32Integrity), tambahkan di sini.
