# Oblivion Eye (Garuda Hack Shield)

## Ringkasan
Anti-cheat modular user-mode untuk Ragnarok (RRO.exe) ditulis dalam C++17 (VS2022, Win32/x86). Fokus utama: deteksi tool injeksi umum, hook (IAT / inline / prolog), modifikasi memory section kritikal (.text sistem), aktivitas overlay, dan integritas file/signature.

## Arsitektur Tingkat Tinggi
- DLL Client (Oblivion_Client) diinject / diload ke proses game.
- Server contoh (Oblivion_Server) menerima log (Named Pipe) dan mengirim perintah kontrol (command pipe).
- Komunikasi teks sederhana: setiap pesan satu line (terminated `\n`).
- Skema obfuscation opsional: XOR statik / rolling XOR + nonce + CRC32.
- Policy file eksternal untuk memuat blacklist, whitelist publisher / overlay, target prolog, chunk integrity whitelist, dan interval override detector.
- Semua detector (kecuali bootstrap ProcessWatcher WMI thread) berjalan dalam satu `DetectorScheduler` (tick-based) sehingga manajemen interval & profiling terpusat.

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
15. Integrity (.text hashing + delta per-chunk 4096B) untuk: Ntdll / Kernel32 / User32 / Gdi32
16. Rolling XOR + Nonce per pesan + rotasi kunci runtime (PIPE_SET_XOR_KEY) + optional reset nonce
17. CRC32 tagging opsional (integritas pesan)
18. PolicyManager (load/save runtime konfigurasi; mendukung [interval])
19. IntegrityChunkWhitelist (persist ke policy)
20. RuntimeStats (GET_STATUS: deteksi, info, heartbeat, uptime)
21. Command rate limiting (global 20 per 3s) + cooldown khusus perintah berisiko
22. DetectorScheduler: profiling (runCount, last ms, avg ms), adaptive interval, interval override per detector
23. Self-test framework (SELFTEST) untuk mengukur durasi eksekusi langsung tiap detector
24. Perintah manajemen interval: SET_INTERVAL / CLEAR_INTERVAL / CLEAR_INTERVAL_ALL / LIST_INTERVALS / RESET_PROFILER
25. Risk command cooldown (KILL_PROCESS & QUARANTINE_FILE minimal 2s + abuse counter)

## Scheduler & Adaptive Profiling
- Setiap detector memiliki interval dasar (`IntervalMs()`).
- Profiling otomatis mengukur `lastDurationMs` dan `avgDurationMs`.
- Adaptive mode internal: jika rata-rata > 75ms dan belum override manual ? interval dinaikkan bertahap (maks 4x base). Jika < 25ms dan sudah melebar ? diturunkan secara bertahap ke base.
- Override manual (SET_INTERVAL) menonaktifkan adaptasi untuk detector tersebut sampai di-clear.
- RESET_PROFILER menghapus statistik (tidak mengubah interval).
- SELFTEST mengeksekusi semua `Tick()` secara sinkron untuk audit cepat (hasil dalam ms atau ERR).

## Format Pesan Log
- `INFO|Tag|Detail`
- `DETECTION|Feature|Detail`
- PROLOG_LIST:
  - `INFO|PROLOG|BEGIN_PROLOG_LIST count=N`
  - `INFO|PROLOG|<module> <function> <minBytes>` (tiap target)
  - `INFO|PROLOG|END_PROLOG_LIST`
- STATUS: `INFO|STATUS|STATUS detections=X info=Y heartbeats=Z uptime_sec=T`
- Hasil command / operasi runtime lain menggunakan tag khusus: `INFO|RESULT|...`, `INFO|INTERVALS|...`, `INFO|SELFTEST|...`

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
POLICY_LOAD <full_path_policy>
POLICY_SAVE <full_path_policy>
WHITELIST_CHUNK_ADD <module> <chunkIndex>
SET_INTERVAL <DetectorName> <ms>
CLEAR_INTERVAL <DetectorName>
CLEAR_INTERVAL_ALL
LIST_INTERVALS
RESET_PROFILER
SELFTEST
GET_STATUS
```

### Catatan Command Baru
- `SET_INTERVAL` / `CLEAR_INTERVAL` memodifikasi interval scheduler tanpa rebuild.
- `LIST_INTERVALS` menampilkan `<nama>=<ms>` (tanda `*` jika override manual aktif).
- `RESET_PROFILER` menghapus statistik (interval tetap).
- `SELFTEST` mengukur durasi aktual tick masing-masing detector satu kali.
- Cooldown: `KILL_PROCESS` & `QUARANTINE_FILE` minimal 2000 ms antar eksekusi; percobaan terlalu cepat menghasilkan pesan COOLDOWN (dibatasi 5 notifikasi, sisanya silent).

## Policy File Format (UTF-8)
Section order bebas; baris kosong / `#` diabaikan.
```
[process]
cheatengine.exe
[module]
dbghelp.dll
[driver]
dbk32.sys
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
[interval]
heartbeat 10000
antiinjection 7000
```
Catatan:
- Semua entry dipaksa lowercase saat load.
- `prolog`: `<module> <func> <minBytes>`.
- `chunk_whitelist`: `<module> <chunkIndex>` (index 0, chunk 4096B).
- `interval`: `<detector_name_lower> <ms>`; override adaptif dan manual di-set sebelum scheduler start.

## Cara Menggunakan (Ringkas)
1. Build solution (Client DLL + Server exe).
2. Injeksi / load DLL client ke proses game (launcher internal / manual). Pipe server opsional (client retry connect).
3. (Opsional) `PIPE_SET_XOR_KEY 5a`, `PIPE_ROLLING_XOR_ON`, `PIPE_SET_CRC_ON`.
4. `POLICY_LOAD file.policy` untuk konfigurasi awal (atau fallback embedded).
5. Pantau `DETECTION|...` – proses akan dihentikan oleh `ShowDetectionAndExit` untuk event kritis.
6. Kelola hooks prolog: `PROLOG_ADD_TARGET`, lalu `PROLOG_REBASELINE`, cek `PROLOG_LIST`.
7. Whitelist chunk OS update: pakai output Integrity mismatch ? `WHITELIST_CHUNK_ADD`, lalu `POLICY_SAVE`.
8. Atur interval dynamic: `SET_INTERVAL AntiInjection 8000`, atau reset: `CLEAR_INTERVAL AntiInjection` / `CLEAR_INTERVAL_ALL`.
9. Audit kinerja: `SELFTEST`, atau profiling ringkas via `GET_STATUS`.

## Heartbeat Adaptif
- Interval dasar (misal 10s) dapat dinaikkan ketika sistem idle; pengaturan adaptif ON/OFF via command.

## Rolling XOR + Nonce
- Format: `NONCE=xxxxxxxx;<payload_obfuscated>`
- `PIPE_SET_XOR_KEY <hex>` mereset nonce.

## CRC32 Tagging
- Diaktifkan via `PIPE_SET_CRC_ON`; pesan memiliki suffix `|CRC=XXXXXXXX` sebelum obfuscation.

## Delta & Chunk Whitelist
- Full mismatch ? re-hash per chunk 4KB; hanya chunk bukan whitelist ? deteksi.

## Runtime Stats & Profiling
- `GET_STATUS` menampilkan ringkas rata-rata ms (maks 10 detector pertama yang sudah run >0 kali).
- `LIST_INTERVALS` menampilkan interval aktif (tanda `*` = override manual; adaptif tidak diberi tanda khusus saat ini).

## Self Test
- `SELFTEST` menjalankan satu siklus `Tick()` semua detector secara serial dan mengembalikan durasi ms per nama.
- Berguna untuk baseline performa / investigasi lag.

## Keamanan & Limitasi
- User-mode only; tidak mencegah driver ring-0.
- Inline hook detection terbatas prolog awal.
- Hash .text sensitif terhadap patch OS (gunakan whitelist).
- Obfuscation channel bukan kriptografi kuat.
- Rate limit command global & cooldown risk command mencegah flood dasar; tidak menggantikan ACL pipe.

## Rekomendasi Deployment
1. Sertakan embedded fallback policy.
2. Sign DLL client.
3. Atur ACL pipe (PRODUCTION) untuk batasi akses.
4. Rotasi kunci XOR berkala.
5. Simpan policy terenkripsi (opsional) & verifikasi signature.

## Build
- VS2022, C++17.
- Release Win32.

## Pengujian Cepat
1. Jalankan PipeServer & PipeCommandServer.
2. Load DLL di game.
3. `GET_STATUS` (cek uptime, profiling bertambah).
4. `PROLOG_LIST` valid.
5. Patch byte dummy (simulasi) ? trigger detection.
6. Tambah whitelist chunk ? simpan policy ? verifikasi tidak deteksi lagi.
7. `SELFTEST` dan periksa waktu eksekusi.

## Lisensi
Hanya untuk proteksi aplikasi Anda sendiri. Tidak untuk distribusi publik tanpa izin penulis.
