Oblivion Eye (Garuda Hack Shield)

Ringkasan
- Anti-cheat modular untuk Ragnarok (RRO.exe) berbasis user-mode (C++14, VS2022, Win32/x86).
- Client side: Dynamic DLL (dllmain.cpp) di proyek Oblivion_Client.
- Server side: Console app (server.cpp) di proyek Oblivion_Server.
- Hooking DLL ke RRO.exe menggunakan Stud_PE (DLL Import) dengan fungsi export: OblivionEye_Entry.
- Desain ringan: initial scan sekali, setelah itu event-driven/polling ringan, berhenti saat deteksi.

Struktur Folder
- Oblivion_Client/
  - include/ -> semua header (.h)
  - src/ -> semua implementasi (.cpp)
  - dllmain.cpp -> entry DLL, start/stop semua modul
- Oblivion_Server/
  - Server.cpp -> main server console (log pipe)
  - src/PipeServer.cpp -> implementasi named pipe server (log)
  - src/PipeCommandServer.cpp -> named pipe command server (kirim perintah ke client)

Persiapan Project di VS2022
- Buka solusi di VS2022.
- Platform: Win32 (x86).
- C++ Language Standard: C++14.
- Toolset: VS 2022 (v143).
- Precompiled Headers (pch.h/pch.cpp) aktif (default template VS).

Hooking DLL ke RRO.exe (Stud_PE)
- Build Oblivion_Client (Debug/Release Win32) untuk menghasilkan Oblivion_Client.dll.
- Copy DLL ke folder yang sama dengan RRO.exe.
- Ikuti panduan: https://docs.herc.ws/client/dll-import
  - Tambahkan import ke RRO.exe:
    - DLL Name: Oblivion_Client.dll (atau nama DLL Anda)
    - Function: OblivionEye_Entry (export sudah disediakan)
- Simpan hasil patch. Jalankan RRO.exe untuk memuat DLL otomatis.

Cara Menjalankan Server Contoh
- Set startup project ke Oblivion_Server (console).
- Jalankan Pipe log server (PipeServer) untuk menerima log: \\.\pipe\OblivionEye.
- Jalankan Pipe command server (PipeCommandServer) untuk mengirim perintah: \\.\pipe\OblivionEyeCmd.
- Jalankan RRO.exe (dengan DLL). Client akan connect ke dua pipe tersebut.

Fitur (Basic) yang Sudah Selesai
1) Process & Thread Watcher
   - Scan proses 1x saat start, lalu monitor proses baru (WMI event jika tersedia, fallback polling). Jika nama exe ada di blacklist -> deteksi & close.
   - Daftar proses blacklist: Oblivion_Client/src/Blacklist.cpp (bisa diupdate saat runtime via UPDATE_BLACKLIST)
2) Heartbeat System
   - Log status berkala (OutputDebugString) + kirim INFO via pipe. Interval default 10 detik.
3) Overlay Scanner
   - Enumerasi window visible, cocokkan title/class substring blacklist. Interval default 2 detik.
   - Daftar overlay: src/OverlayBlacklist.cpp (bisa diupdate via UPDATE_OVERLAY_BLACKLIST_TITLE/CLASS)
4) Driver Scanner (usermode)
   - EnumDeviceDrivers + GetDeviceDriverBaseNameW. Cocokkan nama driver dengan blacklist. Interval 10 detik.
   - Daftar driver: src/DriverBlacklist.cpp
5) Anti Debug
   - IsDebuggerPresent + NtQueryInformationProcess (DebugPort/Flags/Object). Interval 3 detik.
6) Anti Suspend Threads
   - Registry TID dan auto-ResumeThread untuk menjaga thread tidak disuspend.
7) Anti Injection (Module Enumeration)
   - EnumProcessModules + GetModuleBaseNameW. Cocokkan modul ter-load dengan blacklist. Interval 5 detik.
   - Daftar modul: src/ModuleBlacklist.cpp (bisa diupdate saat runtime via UPDATE_MODULE_BLACKLIST)
8) Digital Signature Scanner
   - Kebijakan: jika whitelist publisher (PublisherWhitelist) tidak kosong, file kritikal wajib signed-by-trusted; jika kosong, cukup signed.
   - Path file kritikal ditambahkan via API AddCriticalPath (lihat dllmain.cpp -> TODO). Interval 15 detik.
9) Anti TestMode (Windows /testsigning)
   - Cek registry CodeIntegrity TestFlags != 0. Interval 15 detik.
10) Signature Scanner (Memory Pattern)
   - Pencocokan pola byte terhadap image module. Interval 20 detik. Default signature list kosong untuk minim false positive.
   - Tambahkan pola di src/Signatures.cpp.
11) Pipe Communication (Named Pipe)
   - Log server: \\.\pipe\OblivionEye. Command server: \\.\pipe\OblivionEyeCmd. Perintah: CLOSE_CLIENT, UPDATE_BLACKLIST <process.exe>, UPDATE_MODULE_BLACKLIST <dllname>, UPDATE_OVERLAY_BLACKLIST_TITLE <title>, UPDATE_OVERLAY_BLACKLIST_CLASS <class>, REQUEST_HEARTBEAT_NOW.
   - Client kirim log via PipeClient, menerima perintah via PipeCommandClient.
12) Hijacked Thread Detector (advanced)
   - NtQueryInformationThread (class 9) untuk start address thread, validasi berada pada module proses.
13) IAT Hook Checker
   - Cek IAT entry per module, validasi target address berada dalam module owner.
14) Test Mode Spoof Checker (basic)
   - Placeholder deteksi spoof (default aman/false).
15) HWID Generator (basic)
   - Volume Serial + CPU Name + MAC -> hash sederhana (FNV-like). Untuk identitas unik.
16) File Integrity Checker (MD5)
   - MD5 via WinCrypt. Untuk validasi file seperti RRO.exe/.grf.
17) TCP Client (opsional)
   - Queue non-blocking, auto-reconnect, kirim ke host:port.
18) Handle Protection (anti-hijack basic)
   - Drop SeDebugPrivilege dan perketat DACL proses (SYSTEM & owner full). Diterapkan sangat awal saat attach.

Update Versi Advanced
- ProcessWatcher: migrasi ke WMI event untuk proses baru (fallback ke polling jika WMI gagal).
- EventReporter: semua deteksi utama mengirim log ke server via pipe.
- PublisherWhitelist: whitelist publisher tepercaya (CN) + integrasi dengan DigitalSignatureScanner & AntiInjection.
- Command channel: PipeCommandClient (client) + PipeCommandServer (server) untuk perintah dari server (CLOSE_CLIENT, UPDATE_BLACKLIST, UPDATE_MODULE_BLACKLIST, UPDATE_OVERLAY_BLACKLIST_TITLE/CLASS, REQUEST_HEARTBEAT_NOW).

Prinsip Desain
- Modular, ringan, minim false positive, fail-fast pada deteksi.

Konfigurasi & Kustomisasi
- Blacklist proses: src/Blacklist.cpp (bisa diupdate runtime via UPDATE_BLACKLIST pada command server)
- Blacklist overlay: src/OverlayBlacklist.cpp (bisa diupdate via UPDATE_OVERLAY_BLACKLIST_TITLE/CLASS)
- Blacklist driver: src/DriverBlacklist.cpp
- Blacklist modul/dll: src/ModuleBlacklist.cpp (bisa diupdate via UPDATE_MODULE_BLACKLIST)
- Signature memory: src/Signatures.cpp
- Path verifikasi digital signature: DigitalSignatureScanner::AddCriticalPath di dllmain.cpp
- Interval scanning: Start(intervalMs) di dllmain.cpp
- Event logging: EventReporter::SendInfo/SendDetection
- Whitelist publisher: PublisherWhitelist::AddTrusted(L"cn publisher lowercase")

Cara Uji Lokal
1) Build solusi (Debug Win32) -> pastikan sukses.
2) Jalankan Pipe log server (Oblivion_Server/src/PipeServer.cpp). Jalankan Pipe command server (Oblivion_Server/src/PipeCommandServer.cpp).
3) Hook DLL ke RRO.exe pakai Stud_PE (OblivionEye_Entry).
4) Jalankan RRO.exe.
5) Kirim perintah dari command server: CLOSE_CLIENT, UPDATE_BLACKLIST cheatengine.exe, UPDATE_MODULE_BLACKLIST dbghelp.dll, UPDATE_OVERLAY_BLACKLIST_TITLE "cheat engine", REQUEST_HEARTBEAT_NOW, dll.
6) Uji deteksi (cheatengine.exe, overlay, driver CE, debugger). Cek log masuk ke server.

Roadmap Advanced Selanjutnya
- Overlay whitelist by publisher (overlay resmi Discord/Steam ditandai trusted).
- Digital signature verification lebih ketat (revocation/chain) + cache hasil verifikasi untuk performa.
- Anti-injection heuristik path (block modul dari folder temp/Users/AppData kecuali whitelist).
- IAT/Inline hook checker prolog API dan guard IAT.
- Server command tambahan: KILL_PROCESS <pid>, QUARANTINE_FILE <path>, UPDATE_DRIVER_BLACKLIST <driver.sys>, WHITELIST_PUBLISHER_ADD <CN>, WHITELIST_FILE_ADD <path>.

Catatan Integrasi Stud_PE (Penting)
- Pastikan nama fungsi export tepat: extern "C" __declspec(dllexport) void OblivionEye_Entry().
- Setelah patch, jika RRO.exe crash saat start, cek dependency DLL (path, arsitektur x86), dan matikan modul opsional (TCP) dahulu.

Kontribusi/Modifikasi
- Semua modul berada di include/src. Tambahkan file baru mengikuti pola yang sama.
- Gunakan gaya konservatif untuk mencegah false positive.

Lisensi/Legal
- Hanya gunakan untuk proteksi aplikasi Anda sendiri. Jangan gunakan untuk tujuan yang melanggar hukum.
