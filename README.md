# Oblivion Eye (Garuda Hack Shield)

## Ringkasan
Anti?cheat modular user?mode untuk Ragnarok (RRO.exe) ditulis dalam C++17 (VS2022, Win32/x86). Fokus utama: deteksi tool injeksi umum, hook (IAT / inline / prolog), modifikasi memory section kritikal (.text sistem), aktivitas overlay, dan integritas file/signature.

## Arsitektur Tingkat Tinggi
- DLL Client (Oblivion_Client) diinject / diload ke proses game.
- Server contoh (Oblivion_Server) menerima log (Named Pipe) dan mengirim perintah kontrol (command pipe).
- Komunikasi teks sederhana: setiap pesan satu line (terminated `\n`).
- Skema obfuscation opsional: XOR statik / rolling XOR + nonce + CRC32.
- Policy file eksternal untuk memuat blacklist, whitelist publisher / overlay, target prolog, dan chunk integrity whitelist.

## Fitur Utama
1. Process & Thread Watcher (WMI + fallback snapshot)
2. HandleProtection (mencegah open handle berbahaya – pendekatan dasar)
3. Heartbeat (interval tetap atau adaptif)
4. Overlay Scanner (window title & class blacklist) + Publisher Whitelist
5. Driver Scanner (enumerasi driver user-mode via SCM / snapshot)
6. AntiDebug (heuristik anti attach debugger)
7. AntiSuspend (monitor thread freeze / suspend)
8. AntiInjection (proses / modul blacklist, heuristic injeksi dasar)
9. DigitalSignatureScanner (verifikasi file kritikal + whitelist publisher)
10. AntiTestMode & TestModeSpoofChecker
11. SignatureScanner (pattern memory sederhana)
12. HijackedThreadDetector (context / start address anomaly check)
13. IATHookChecker (validasi pointer import)
14. PrologHookChecker (inline prolog baseline + penambahan target dinamis + PROLOG_LIST)
15. Integrity:
    - NtdllIntegrity / Kernel32Integrity / User32Integrity / Gdi32Integrity
    - Full .text hash + delta hashing per chunk 4096 byte
    - Chunk whitelist untuk mengabaikan patch OS resmi
16. Rolling XOR + Nonce per pesan + rotasi kunci runtime (PIPE_SET_XOR_KEY) + optional reset nonce
17. CRC32 tagging opsional (integritas pesan)
18. PolicyManager (load/save runtime konfigurasi)
19. IntegrityChunkWhitelist (persist ke policy)
20. RuntimeStats (GET_STATUS: deteksi, info, heartbeat, uptime)
21. PipeCommandClient (eksekusi command server) & PipeClient (kirim log)

## Format Pesan Log
- `INFO|Tag|Detail`
- `DETECTION|Feature|Detail`
- PROLOG_LIST:
  - `INFO|PROLOG|BEGIN_PROLOG_LIST count=N`
  - `INFO|PROLOG|<module> <function> <minBytes>` (tiap target)
  - `INFO|PROLOG|END_PROLOG_LIST`
- STATUS: `INFO|STATUS|STATUS detections=X info=Y heartbeats=Z uptime_sec=T`

## Daftar Command (PipeCommandServer)
```
CLOSE_CLIENT
UPDATE_BLACKLIST <process.exe>
UPDATE_MODULE_BLACKLIST <dllname>
UPDATE_OVERLAY_BLACKLIST_TITLE <title>
UPDATE_OVERLAY_BLACKLIST_CLASS <class>
UPDATE_DRIVER_BLACKLIST <driver.sys>
WHITELIST_PUBLISHER_ADD <CN>
WHITELIST_FILE_ADD <full_path>
KILL_PROCESS <pid>
QUARANTINE_FILE <full_path>
REQUEST_HEARTBEAT_NOW
PROLOG_ADD_TARGET <module> <func> [bytes]
PROLOG_REBASELINE
PROLOG_LIST
PIPE_SET_XOR_KEY <hex_byte>
PIPE_SET_CRC_ON
PIPE_SET_CRC_OFF
PIPE_ROLLING_XOR_ON
PIPE_ROLLING_XOR_OFF
HEARTBEAT_ADAPTIVE_ON
HEARTBEAT_ADAPTIVE_OFF
POLICY_LOAD <full_path_to_policy>
POLICY_SAVE <full_path_to_policy>
WHITELIST_CHUNK_ADD <module> <chunkIndex>
GET_STATUS
exit
```

## Policy File Format (UTF?8)
Section order bebas; baris kosong / `#` diabaikan.
```
[process]
cheatengine.exe
...
[module]
dbghelp.dll
...
[driver]
dbk32.sys
...
[overlay_title]
cheat engine
[overlay_class]
discordoverlay
[publisher]
microsoft corporation
gravity co., ltd.
[prolog]
kernel32.dll VirtualProtect 8
ntdll.dll NtOpenProcess 8
[chunk_whitelist]
ntdll.dll 5
kernel32.dll 12
```
Catatan:
- Semua entry otomatis dilowercase saat load.
- PROLOG format: `<module> <func> <minBytes>`.
- chunk_whitelist: `<module> <chunkIndex>` (index berbasis 0, ukuran chunk 4096 byte).

## Cara Menggunakan
1. Build solution (Client DLL + Server exe).
2. Injeksi / load DLL client ke proses game (misal via launcher internal). Pastikan Named Pipe server siap (opsional; client akan retry koneksi log).
3. Jalankan PipeServer (log) dan PipeCommandServer (command) atau gabung keduanya sesuai kebutuhan.
4. (Opsional) Kirim `PIPE_SET_XOR_KEY 5a` lalu `PIPE_ROLLING_XOR_ON` dan `PIPE_SET_CRC_ON` untuk aktivasi proteksi channel.
5. (Opsional) `POLICY_LOAD file.policy` untuk muat konfigurasi awal.
6. Pantau log: setiap deteksi menghasilkan `DETECTION|...` dan proses akan terminasi (ShowDetectionAndExit) untuk event kritikal.
7. Tambah target prolog runtime: `PROLOG_ADD_TARGET kernel32.dll CreateFileW 8` kemudian `PROLOG_REBASELINE` bila ingin baseline langsung.
8. Lihat daftar target: `PROLOG_LIST`.
9. Jika integritas mod mismatch akibat update Windows, catat chunk yang terdeteksi (misal `[5@0x00005000]`), whitelist: `WHITELIST_CHUNK_ADD ntdll.dll 5`, lalu `POLICY_SAVE policy.txt`.
10. Validasi status: `GET_STATUS`.

## Heartbeat Adaptif
- Default interval awal: 10s.
- Setiap 3 tick tanpa deteksi -> interval *2 (maks 60s) saat adaptif ON.
- Reset ke interval dasar ketika adaptif dimatikan atau modul dinonaktifkan.

## Rolling XOR + Nonce
- Packet format client -> server: `NONCE=xxxxxxxx;<payload_obfuscated>`
- Kunci dasar dirotasi: `PIPE_SET_XOR_KEY <hex>` (nonce reset ke 1).
- Rolling mode ON menambah variasi per byte: baseKey ^ ((nonce >> (i % 24)) & 0xFF) ^ (i * 31).

## CRC32 Tagging
- Diaktifkan via `PIPE_SET_CRC_ON`.
- Suffix pesan sebelum obfuscation: `|CRC=XXXXXXXX` (hex uppercase big?endian representasi CRC32).

## Delta & Chunk Whitelist
- Jika full hash mismatch, modul integrity melakukan hashing tiap chunk 4KB.
- Hanya chunk berbeda yang tidak di-whitelist memicu deteksi.
- Gunakan `WHITELIST_CHUNK_ADD <module> <idx>` untuk chunk yang dianggap benign.
- Persist ke policy melalui `[chunk_whitelist]` setelah `POLICY_SAVE`.

## Runtime Stats
- `GET_STATUS` output: `INFO|STATUS|STATUS detections=X info=Y heartbeats=Z uptime_sec=T`.
- Detections = jumlah pemanggilan EventReporter::SendDetection (biasanya diikuti exit cepat).

## Prolog Hook Checker
- Baseline default target API sensitif injeksi.
- Tambah target runtime -> `PROLOG_ADD_TARGET <mod> <func> [bytes]`.
- `PROLOG_LIST` untuk enumerasi.
- `PROLOG_REBASELINE` rekalkulasi baseline (gunakan setelah serangkaian add / load policy).

## Integritas Section (.text)
- Hash awal + vector hash chunk (4096B).
- Mismatch dengan semua perubahan chunk ter-whitelist => diabaikan (tidak deteksi).
- Cegah patching inline / hooking API kritikal user-mode.

## Logging & Monitoring
Rekomendasi: pipe consumer mem-parsing prefix (INFO / DETECTION / PROLOG / STATUS) untuk routing ke dashboard / SIEM.

## Keamanan & Limitasi
- User-mode only; tidak mencegah driver ring?0 atau kernel tampering.
- Inline hook detection prolog sederhana (pattern awal umum; bisa dilewati teknik lanjutan / mid-function patching kompleks).
- Hash .text sensitif pada pembaruan OS (gunakan whitelist).
- Tidak ada anti kernel handle duplication.
- Obfuscation channel bukan kriptografi kuat (rolling XOR + CRC32 hanya melawan sniffing ringan).

## Rekomendasi Deployment
1. Hardcode minimal base policy di DLL (fallback) + load remote policy setelah start.
2. Sign DLL client.
3. Restrict akses pipe (ACL) di production.
4. Rotasi kunci XOR secara berkala (PIPE_SET_XOR_KEY).
5. Simpan policy terenkapsulasi (opsional encrypt) untuk mencegah manipulasi.

## Build
- Buka solusi di VS2022.
- Set toolset C++ terbaru (std >= C++17).
- Build konfigurasi Release Win32.

## Pengujian Cepat
1. Jalankan PipeServer & PipeCommandServer.
2. Launch proses game dengan DLL ter-load.
3. Kirim `GET_STATUS` (pastikan uptime & heartbeat meningkat).
4. Kirim `PROLOG_LIST` (lihat daftar target).
5. Patch byte di kernel32!VirtualProtect (simulasi) -> harus DETECTION.
6. Tambah whitelist chunk (jika ingin mensimulasikan patch OS) -> pastikan tidak lagi memicu deteksi.

## Lisensi
Hanya untuk proteksi aplikasi Anda sendiri. Tidak untuk distribusi publik tanpa izin penulis.
