![Build Status](https://img.shields.io/badge/build-passing-brightgreen?style=flat-square)
![Platform](https://img.shields.io/badge/platform-Windows-blue?style=flat-square)
![C++](https://img.shields.io/badge/C++-20-blue?style=flat-square)
![License](https://img.shields.io/badge/license-Private-red?style=flat-square)

Oblivion Eye adalah **sistem Anti-Cheat** tingkat lanjut untuk game MMORPG.  
Dibuat dengan **C++20** di **Visual Studio 2022**, terdiri dari **client-side DLL** dan **server-side console app** yang terhubung lewat **TCP Socket (WinSock)** untuk mendeteksi, memblokir, dan melaporkan cheat secara real-time.

---

## ✨ Fitur Utama

### Client-Side Modules (`OblivionEye_Client/include/` & `src/`)
- **AntiDebug** – Deteksi debugger dengan API `IsDebuggerPresent`, `NtQueryInformationProcess`, dsb.
- **AntiSuspend** – Mencegah thread game dihentikan (anti-freeze).
- **Blacklist** – Daftar proses/aplikasi cheat yang diblokir.
- **EncryptionHandler** – Enkripsi komunikasi data ke server.
- **FileIntegrityChecker** – Validasi file penting game lewat hash MD5/SHA256.
- **HijackDetector** – Deteksi thread atau fungsi yang dihook oleh cheat.
- **HWIDSystem** – Identifikasi perangkat unik untuk anti-multi-akun/ban bypass.
- **IATHookScanner** – Deteksi hook pada Import Address Table (API hooking).
- **InjectionScanner** – Deteksi modul/DLL injection.
- **Logger** – Logging event anti-cheat ke file dan server.
- **MemoryScanner** – Scan signature cheat di memori proses game.
- **OverlayScanner** – Deteksi dan hancurkan window overlay (ESP, wallhack UI).
- **ProcessWatcher** – Monitor dan matikan proses cheat yang terdeteksi.
- **ServerCommunication** – Modul TCP client untuk kirim log ke server.
- **SignatureValidator** – Validasi tanda tangan digital file (opsional).

### Server-Side Modules (`OblivionEye_Server/include/` & `src/`)
- **ClientSession** – Manajemen koneksi dari client anti-cheat.
- **EncryptionHandler** – Dekripsi & enkripsi data komunikasi.
- **HeartbeatManager** – Memastikan client aktif dan tidak dimodifikasi.
- **ServerLogger** – Logging event ke file `server.log`.

---

## 🖥 Arsitektur Sistem

graph TD
    subgraph Client
        A1[ProcessWatcher]
        A2[OverlayScanner]
        A3[AntiDebug]
        A4[InjectionScanner]
        A5[MemoryScanner]
        A6[FileIntegrityChecker]
        A7[HWIDSystem]
        A8[Logger]
        A9[EncryptionHandler]
    end

    subgraph Server
        B1[Log Receiver]
        B2[Validation Engine]
        B3[Response System]
        B4[HeartbeatManager]
    end

    A1 --> A8
    A2 --> A8
    A3 --> A8
    A4 --> A8
    A5 --> A8
    A6 --> A8
    A7 --> A8
    A8 --> A9
    A9 -->|TCP Socket| B1
    B1 --> B2
    B2 --> B3
    B2 --> B4

🔍 Flow Chart Deteksi Cheat
flowchart TD
    Start([Mulai]) --> Init[Inisialisasi Modul Anti-Cheat]
    Init --> ScanProc[ProcessWatcher: Scan proses & thread]
    ScanProc --> CheckOverlay[OverlayScanner: Scan overlay]
    CheckOverlay --> CheckDebug[AntiDebug: Deteksi debugger]
    CheckDebug --> ScanInject[InjectionScanner: Scan DLL injection]
    ScanInject --> MemScan[MemoryScanner: Signature scan memori]
    MemScan --> Integrity[FileIntegrityChecker: Validasi file]
    Integrity --> HWID[HWIDSystem: Generate & kirim HWID]
    HWID --> SendLog[ServerCommunication: Kirim log]

    SendLog -->|Cheat Ditemukan| ServerKick[Server: Kick/Ban]
    SendLog -->|Bersih| LoopKembali[Ulang scan]
    ServerKick --> End([Selesai])
    LoopKembali --> ScanProc

📊 Tabel Perbandingan Cheat vs Metode Deteksi
Jenis Cheat	Metode Deteksi	Modul yang Bertugas
Cheat Engine	Process Scan, Memory Scan	ProcessWatcher, MemoryScanner
Wallhack / ESP Overlay	Window Enumeration & Destroy	OverlayScanner
Speedhack	API Hook Detection, Timer Validation	IATHookScanner
Bot (OpenKore)	Process Scan, Packet Analysis	ProcessWatcher
Packet Editor (WPE)	API Hook Detection, Socket Validation	IATHookScanner, ServerValidation
DLL Injection	Module Enumeration	InjectionScanner
Debugger	API Detection, NtQuery	AntiDebug

📑 Contoh Config File Signature (MD5)
[
    {
        "file": "RRO.exe",
        "md5": "A3B2C1D4E5F67890123456789ABCDEF0"
    },
    {
        "file": "data.grf",
        "md5": "1234567890ABCDEF1234567890ABCDEF"
    }
]

🚀 Cara Build
Clone Repository
git clone https://github.com/Hansel38/Oblivion.git
cd Oblivion
Buka Project di Visual Studio 2022
Platform Toolset: v143
C++ Language Standard: ISO C++20
Build Client dan Server
Gunakan Release Mode untuk produksi.
Compile OblivionEye_Client dan OblivionEye_Server.

🔧 Cara Integrasi ke Game
Client-Side
Inject OblivionEye_Client.dll ke proses game.
Pastikan config dan signature list sesuai kebutuhan.
Server-Side
Jalankan OblivionEye_Server.exe.
Pastikan port TCP sesuai di client & server.

📜 Lisensi
Project ini bersifat private research dan tidak untuk distribusi publik tanpa izin.

📩 Kontak
Author: Hansel38

GitHub: https://github.com/Hansel38
