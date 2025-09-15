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
26. Overlay Scanner diperluas dengan heuristik struktur window (deteksi varian Cheat Engine rebrand)
27. SignatureScanner memuat pola dasar CE (speedhack jump stub, UI string cluster)
28. PrologHookChecker kini juga baseline timing API (GetTickCount/QueryPerformanceCounter/NtQueryPerformanceCounter/NtDelayExecution)
29. AntiInjection menambahkan probing artefak device driver CE (\\.\DBKKernel / DBKProc / DBKPhys) dengan cooldown
30. Dynamic Signature Loading via policy section baru `[signature]` (memungkinkan update pola tanpa rebuild)
31. External Intrusive Handle Detection (enumerasi system handle mendeteksi proses lain memegang akses WRITE/VM/DEBUG ke proses game)
32. Weighted Multi-Source Correlation Engine (korelasi hook + partial heuristic/signature + external handle untuk peningkatan confidence dan reduksi false positive)

## Scheduler & Adaptive Profiling

- Setiap detector memiliki interval dasar (`IntervalMs()`).
- Profiling otomatis mengukur `lastDurationMs` dan `avgDurationMs`.
- Adaptive mode internal: jika rata-rata > ADAPT_INCREASE_THRESHOLD (default 75ms) dan belum override manual → interval dinaikkan bertahap (maks ADAPT_INTERVAL_MULT_MAX x base, default 4x). Jika < ADAPT_DECREASE_THRESHOLD (default 25ms) dan sudah melebar → diturunkan bertahap ke base.
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

```text
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
DUMP_CONFIG
SIGNATURE_LIST
CORR_STATUS
CORR_STATUS_JSON
CORR_RESET
```

### Catatan Command Baru

- `SET_INTERVAL` / `CLEAR_INTERVAL` memodifikasi interval scheduler tanpa rebuild.
- `LIST_INTERVALS` menampilkan `<nama>=<ms>` (tanda `*` jika override manual aktif).
- `RESET_PROFILER` menghapus statistik (interval tetap).
- `SELFTEST` mengukur durasi aktual tick masing-masing detector satu kali.
- Cooldown: `KILL_PROCESS` & `QUARANTINE_FILE` minimal `CMD_RISK_COOLDOWN_MS` (default 2000 ms) antar eksekusi; percobaan terlalu cepat menghasilkan pesan COOLDOWN (dibatasi `CMD_ABUSE_THRESHOLD` notifikasi, sisanya silent).
- `DUMP_CONFIG` menampilkan nilai konfigurasi aktif (constant compile-time) untuk audit cepat.
- `SIGNATURE_LIST` menampilkan daftar signature aktif (nama dan panjang pola) setelah load policy.

## Policy File Format (UTF-8)

Section order bebas; baris kosong / `#` diabaikan.

```text
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
[signature]
# Format: <nama>|<pola_hex>
# Gunakan spasi antar byte; wildcard byte gunakan ??
# Contoh sederhana speedhack stub tambahan (dummy):
ce_speed_stub2|E9 ?? ?? ?? ?? 90 90
ui_first_next_cluster|46 69 72 73 74 20 53 63 61 6E 00 00 00 4E 65 78 74 20 53 63 61 6E
```

Catatan:

- Semua entry dipaksa lowercase saat load.
- `prolog`: `<module> <func> <minBytes>`.
- `chunk_whitelist`: `<module> <chunkIndex>` (index 0, chunk 4096B).
- `interval`: `<detector_name_lower> <ms>`; override adaptif dan manual di-set sebelum scheduler start.
- `signature`: `<name>|<hex pattern>`; hex harus dipisah spasi (`AA BB CC`), `??` = wildcard. Saat policy load, signature bawaan di-clear lalu diganti pattern baru (gunakan kembali pattern bawaan jika masih ingin aktif).

### Dynamic Signature Loading

Section `[signature]` memperbolehkan menambahkan / mengganti pola runtime tanpa rebuild. Implementasi saat load:

1. Ketika parser menemukan `[signature]`, vector internal signature dibersihkan.
1. Setiap baris non-komentar dengan format `<nama>|<pola>` diparse:

- Nama disimpan apa adanya (case dilestarikan untuk log).
- Pola: token dipisah spasi; `??` → wildcard (mask=false), hex (1–2 digit) → byte (mask=true).

1. SignatureScanner menggunakan daftar baru pada tick berikutnya.

Command `SIGNATURE_LIST` dapat dipakai sewaktu-waktu untuk memverifikasi signature mana yang aktif (berguna setelah `POLICY_LOAD`).

Implikasi:

- Semua signature build-in hilang setelah `[signature]` section ditemukan; pastikan salin pola default jika masih ingin menggunakannya.
- Dapat dipakai untuk eksperimen cepat terhadap varian baru tanpa distribusi binary baru.
- Validasi minimal: token >2 hex digit akan mengabaikan baris (silent). Pertimbangkan menambah log error jika perlu.

Rekomendasi:

- Simpan file policy baseline yang berisi pola default + tambahan Anda.
- Gunakan nama konsisten (prefix `ce_`, `tool_`, dll) untuk mempermudah korelasi log.

Contoh minimal hanya signature:

```text
[signature]
ce_speedhack_jmp|E9 ?? ?? ?? ?? 90 90
ce_ui_first_next|46 69 72 73 74 20 53 63 61 6E 00 00 00 4E 65 78 74 20 53 63 61 6E
```

## Cara Menggunakan (Ringkas)

1. Build solution (Client DLL + Server exe).
2. Injeksi / load DLL client ke proses game (launcher internal / manual). Pipe server opsional (client retry connect).
3. (Opsional) `PIPE_SET_XOR_KEY 5a`, `PIPE_ROLLING_XOR_ON`, `PIPE_SET_CRC_ON`.
4. `POLICY_LOAD file.policy` untuk konfigurasi awal (atau fallback embedded).
5. Pantau `DETECTION|...` � proses akan dihentikan oleh `ShowDetectionAndExit` untuk event kritis.
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

Menjalankan satu siklus semua detector secara serial untuk benchmarking cepat performa.

## Correlation Engine

Menggabungkan sinyal (hook, partial heuristic/signature, external handle) dalam jendela `CORR_WINDOW_MS` dan hanya memicu detection korelasi untuk kombinasi bernilai tinggi.

Jalur:

1. HookCorrelation – kombinasi hook (EAT/IAT/PROLOG/SYSCALL) ketika totalScore >= `CORR_SCORE_THRESHOLD`.
2. MultiSourceCorrelation – distinct kategori >= `CORR_TRIGGER_DISTINCT` dan mengandung CE_PARTIAL / SIG_PARTIAL / EXT_HANDLE.

Kategori aktif:

- EAT, IAT, PROLOG, SYSCALL (indikasi hook / manipulasi eksekusi)
- CE_PARTIAL (heuristik UI CE kuat tapi < `CE_SCORE_THRESHOLD`; bobot `CE_PARTIAL_SCORE`)
- SIG_PARTIAL (cluster string/UI saja tanpa stub eksekusi; memberi bobot `SIG_PARTIAL_SCORE` saat belum ada signature kuat lain)
- EXT_HANDLE (proses eksternal memegang akses tinggi: WRITE/VM/THREAD/DEBUG → bobot `EXT_HANDLE_SCORE`)

Skoring & Evaluasi:

- Setiap Report(category, detail, weight) disimpan dengan timestamp.
- Prune tiap `CORR_PRUNE_INTERVAL_MS` untuk buang entri tua.
- Kombinasi unik hanya sekali dilaporkan (cache internal) agar log tidak banjir.

Command: `CORR_STATUS` → contoh `score=5 eat=0 iat=0 prolog=1 syscall=0 ceP=1 sigP=0 handle=1`.
Command JSON: `CORR_STATUS_JSON` → kunci numerik termasuk metrics internal.
Reset state: `CORR_RESET` → flush semua entri, cooldown, dan counter metrics.

Contoh Alur:

1. CE_PARTIAL (2) + EXT_HANDLE (3) → score=5 distinct=2 (belum multi-source).
2. PROLOG hook terdeteksi → distinct=3 → MultiSourceCorrelation tercapai.

Manfaat:

- Turunkan false positive single-signal.
- Tingkatkan confidence sebelum tindakan fatal.
- Observabilitas progres investigasi via `CORR_STATUS`.

Roadmap: aktifkan SIG_PARTIAL nyata; bobot dinamis via policy.

Catatan: Partial event tidak menghentikan proses sendiri; hanya detection akhir atau detector kritikal lain yang memicu exit.

### Heuristik Varian Cheat Engine (Integrasi di Overlay Scanner)

Overlay Scanner tidak lagi hanya mengandalkan substring judul / class. Ia sekarang memberi skor pada window top-level (visible, min 400x300) untuk mengidentifikasi pola UI CE yang di-rebrand:

- +2: class root mengandung `TMainForm` atau `TApplication`
- +2: judul masih mengandung `cheat engine`
- +1: >=2 ListView child
- +1: >=8 Edit control
- +1: child text mengandung `pointer` atau `scan`
- +1: menu memiliki >=3 kata: File / Edit / Table / Memory / Scan

Trigger skor >=4 → `DETECTION|OverlayScanner|CEHeuristic ...` dan proses dihentikan. Cooldown global 5 menit & setiap HWND hanya dilaporkan sekali per sesi. Ini meningkatkan cakupan terhadap build Cheat Engine yang rename file & title namun masih mempertahankan struktur UI dasar.

## Konfigurasi Terpusat (`Config.h`)

Semua angka penting ditempatkan di `include/Config.h` untuk menghindari hard-code tersebar:

| Kategori | Konstanta | Default | Deskripsi |
|----------|-----------|---------|----------|
| Command Rate | `CMD_WINDOW_MS` | 3000 | Jendela sliding ms untuk rate limiting perintah |
| Command Rate | `CMD_MAX_RECENT` | 20 | Maks perintah dalam window sebelum ditolak |
| Risk Cooldown | `CMD_RISK_COOLDOWN_MS` | 2000 | Cooldown perintah berisiko (kill/quarantine) |
| Risk Cooldown | `CMD_ABUSE_THRESHOLD` | 5 | Notifikasi cooldown maksimum sebelum silent |
| Adaptive | `ADAPT_INCREASE_THRESHOLD` | 75.0 | Ambang naikkan interval (ms avg) |
| Adaptive | `ADAPT_DECREASE_THRESHOLD` | 25.0 | Ambang turunkan interval |
| Adaptive | `ADAPT_INTERVAL_MULT_MAX` | 4 | Batas kelipatan interval dasar |
| Scheduler | `SCHED_MIN_SLEEP_MS` | 10 | Clamp sleep loop minimum |
| Slow Alert | `DEFAULT_SLOW_THRESHOLD_MS` | 120.0 | Ambang ms dianggap lambat |
| Slow Alert | `DEFAULT_SLOW_ALERT_STREAK` | 3 | Streak lambat sebelum alert |
| Proc Watch | `PROC_WATCH_POLL_IDLE_MS` | 1200 | Delay fallback saat idle |
| Proc Watch | `PROC_WATCH_POLL_ACTIVE_MS` | 750 | Delay fallback saat ada perubahan |
| Pipe | `PIPE_RECONNECT_MS` | 2000 | Delay reconnect pipe gagal |
| Pipe | `PIPE_IDLE_SLEEP_MS` | 200 | Delay idle saat queue kosong |
| TCP | `TCP_IDLE_SLEEP_MS` | 200 | Delay idle send loop TCP |
| Buffers | `PIPE_CMD_BUFFER` | 1024 | Ukuran buffer baca command pipe |
| Buffers | `TCP_HOST_MAX` | 256 | Batas panjang hostname UTF-8 |
| Buffers | `MODULE_ENUM_MAX` | 1024 | Maks modul saat enumerasi IAT / signature |
| Buffers | `PROCESS_ENUM_RESERVE` | 1024 | Reserve vector snapshot proses |
| Buffers | `WINDOW_TITLE_MAX` | 256 | Buffer judul window overlay |
| Buffers | `CHUNK_SIZE` | 4096 | Ukuran chunk hashing integritas |
| Buffers | `SIGNATURE_SCAN_MAX` | 16MB | Batas maksimum bytes discan signature |
| Buffers | `CAPTURE_MAX` | 256 | Panjang capture stub syscall |
| CE Heuristic | `CE_MIN_WIDTH` | 400 | Minimum lebar window untuk evaluasi CE |
| CE Heuristic | `CE_MIN_HEIGHT` | 300 | Minimum tinggi window untuk evaluasi CE |
| CE Heuristic | `CE_SCORE_THRESHOLD` | 4 | Skor final memicu detection CE |
| CE Heuristic | `CE_COOLDOWN_MS` | 300000 | Cooldown global laporan CE |
| CE Heuristic | `CE_REQ_LISTS` | 2 | Jumlah minimal ListView child untuk +1 skor |
| CE Heuristic | `CE_REQ_EDITS` | 8 | Jumlah minimal Edit control untuk +1 skor |
| CE Heuristic | `CE_UI_HITS_SCORE1` | 1 | Ambang UI hits pertama early stop (dipakai + pola lain) |
| CE Heuristic | `CE_UI_HITS_SCORE2` | 2 | Ambang UI hits kedua early stop (skip sisa) |
| CE Heuristic | `CE_EARLYSTOP_UI` | 3 | Early-stop jika hits UI mencapai nilai ini + indikator lain |
| CE Heuristic | `CE_EARLYSTOP_LISTS` | 2 | Early-stop jika ListView sudah cukup & indikator lain kuat |
| CE Heuristic | `CE_EARLYSTOP_EDITS` | 6 | Early-stop jika Edit control banyak comb dengan indikator lain |
| Handle Scan | `HANDLE_SCAN_COOLDOWN_MS` | 10000 | Cooldown minimal antar enumerasi system handle |
| Handle Scan | `HANDLE_SCAN_MAX_DUP` | 32 | Batas laporan suspicious agar log tidak banjir |
| Correlation | `CORR_WINDOW_MS` | 60000 | Window ms event dikumpulkan untuk korelasi |
| Correlation | `CORR_PRUNE_INTERVAL_MS` | 5000 | Interval prune entri lama |
| Correlation | `CORR_SCORE_THRESHOLD` | 5 | Ambang skor jalur HookCorrelation |
| Correlation | `CORR_TRIGGER_DISTINCT` | 3 | Ambang distinct kategori jalur MultiSourceCorrelation |
| Correlation | `CE_PARTIAL_SCORE` | 2 | Bobot partial CE heuristic (< threshold final) |
| Correlation | `SIG_PARTIAL_SCORE` | 2 | Bobot partial signature (placeholder) |
| Correlation | `EXT_HANDLE_SCORE` | 3 | Bobot event external intrusive handle |
| Correlation | `CORR_STATUS_SNAPSHOT_MS` | 1500 | Interval evaluasi pasif minimal (non highPriority) |
| Correlation | `CORR_DETECTION_COOLDOWN_MS` | 10000 | Cooldown minimal sebelum kombinasi korelasi dikirim lagi |

Ubah nilai sesuai kebutuhan tanpa menyentuh modul lain; rebuild akan menerapkan semuanya.

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

## Test Harness (Integrity + Scheduler + Correlation)

File: `tests/IntegritySchedulerHarness.cpp`
Tambahan:

- `tests/CorrelationHarness.cpp` – uji jalur skor & distinct multi-source.
- `tests/CorrelationConcurrent.cpp` – stress multi-thread Report().
- `tests/CorrelationCooldownHarness.cpp` – verifikasi cooldown detection tidak menggandakan hookDet sebelum waktunya.

Tujuan:

- Menangkap baseline integritas untuk kernel32/ntdll/user32/gdi32 lalu re-check cepat.
- Menjalankan `DetectorScheduler::RunSelfTest()` pada subset detector integritas dan menampilkan durasi.

Cara pakai (tambahkan sebagai proyek console terpisah atau kompilasi manual):

1. Tambah file ke project baru (Console, Unicode, static runtime opsional).
2. Pastikan include path mengarah ke `Oblivion_Client/include`.
3. Link library Windows standar (psapi.lib sudah dipakai oleh beberapa detector).
4. Jalankan; output menampilkan baseline capture dan hasil selftest.

Catatan: Harness tidak membuka pipe; logging detection akan fallback ke stdout bila mekanisme pipe tidak aktif.

## Lisensi

Hanya untuk proteksi aplikasi Anda sendiri. Tidak untuk distribusi publik tanpa izin penulis.
