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

## HMAC Enforcement (2025-09 Update)

Handshake server kini dapat mengumumkan bahwa setiap payload log wajib menyertakan HMAC (SHA-256) dengan respon `OK HMAC` alih-alih hanya `OK`.

Alur:

1. Client kirim `HELLO <nonceCli>`
2. Server kirim `CHALLENGE <nonceSrv>`
3. Client kirim `AUTH <sha256(key + nonceCli + nonceSrv)>`
4. Server validasi dan balas:

   - `OK HMAC` jika `Config::PIPE_HMAC_REQUIRED_DEFAULT == true`
   - `OK` jika tidak diwajibkan

5. Client bila menerima `OK HMAC` otomatis mengaktifkan mode HMAC (menambahkan suffix `|H=<sha256(key_or_sessionKey + payload_plain)>`).

Server Verifikasi:

- Jika `PIPE_HMAC_REQUIRED_DEFAULT` true dan paket tidak memiliki `|H=` → paket dibuang (`[Client][HMACFAIL]`).
- HMAC diverifikasi menggunakan `sessionKey` (hasil derivasi handshake) atau fallback shared key jika session key kosong.

Konfigurasi:

| Konstanta | Efek |
|-----------|------|
| `PIPE_HMAC_REQUIRED_DEFAULT` | True → server balas `OK HMAC` dan drop semua payload tanpa HMAC |

Backward Compatibility:

- Klien lama (tidak paham `OK HMAC`) akan gagal mengirim karena tidak pernah menambahkan HMAC dan paket akan didrop → lakukan rollout serempak.

Rollback Cepat:

1. Set `PIPE_HMAC_REQUIRED_DEFAULT` ke `false` dan rebuild server + client.
2. Server kembali membalas `OK`; klien baru tetap bisa mengirim HMAC (server toleran) karena verifikasi hanya menandai error jika mismatch, bukan ketidakhadiran (kecuali required).

Keamanan:

- HMAC menutup celah modifikasi payload pasca-obfuscation XOR/CRC.
- Disarankan pasang bersama strict handshake ON untuk menghindari downgrade.

## Integrity & Hardening Enhancements (2025-09 Late Update)

Pembaharuan fokus meningkatkan baseline integrity mirip filosofi proteksi Gepard Shield:

1. Hash Upgrade: Semua hashing integrity `.text` kini memakai SHA-256 truncated 64-bit (8 byte LE) menggantikan FNV1a lama (reduksi collision, masih ringkas untuk logging / storage).
2. Optional HWID-Derived HMAC: Baseline `NtdllIntegrity` kini diproteksi HMAC-SHA256 menggunakan kunci obfuscated + campuran hash HWID (aktif secara default lewat `INTEGRITY_HMAC_HWID_ENABLED_DEFAULT`). Mencegah baseline spoof sederhana lintas mesin.
3. Disk Cross-Check Generalized: Delta chunk kini diberi label `(=disk)` bila nilai chunk runtime cocok dengan salinan bersih di disk (module: ntdll, user32; dapat diperluas). Membantu klasifikasi injection in-memory vs patch on-disk.
4. Whitelist Per-Range: `IntegrityChunkWhitelist` mendukung `AddRange` (interval [start,end]) dan melakukan kompresi interval internal. Policy future dapat mengekspose sintaks range tanpa menimbulkan overhead besar.
5. Audit Mode (`MODSEC_AUDIT=1`): Mengaktifkan mode hanya-log (tidak memanggil `ExitProcess`) memudahkan tuning di environment QA / staging tanpa mengganggu runtime pemain.
6. Chained Baseline Persistence: Format baseline `ntdll_baseline.txt` versi 2 memasukkan HMAC versi saat ini dan (opsional) HMAC sebelumnya untuk memitigasi poisoning (injeksi baseline baru tanpa lineage). Konstanta `INTEGRITY_BASELINE_VERSION` menjaga path migrasi.
7. Kernel Surface Stub: Detector placeholder `KernelSurfaceStub` merekam snapshot ringan PEB (pointer Ldr, ProcessParameters, jumlah modul) untuk mendeteksi drift kasar (indikasi manipulasi struktur userland sebelum driver kernel tersedia).
8. Memory Heuristics Detector: `MemoryHeuristics` melakukan sweep region committed mencari halaman eksekusi yang juga writable (RWX) dan mendeteksi entropi tinggi (> ~7.3) pada sampel 4KB. Mengurangi blind spot shellcode JIT / packer yang belum dihook.
9. Config Flags Baru (lihat `Config.h`):

- `INTEGRITY_HMAC_HWID_ENABLED_DEFAULT`
- `INTEGRITY_CHAIN_BASELINE_DEFAULT`
- `MODSEC_AUDIT_MODE_DEFAULT`
- `INTEGRITY_BASELINE_VERSION`
- `INTEGRITY_AUTO_WHITELIST_DISK_MATCH_DEFAULT`

### Perluasan Cakupan Integrity & Multi-Module HMAC (Kernel32 / User32 / Gdi32)

Semua modul inti OS yang dimonitor kini konsisten memakai pipeline integrity yang sama:

- Hashing: SHA-256 truncated 64-bit (`HashUtil::Sha256Trunc64`).
- Chunking: Ukuran mengikuti `Config::CHUNK_SIZE` (seragam di semua modul).
- Disk Cross-Check: Baseline menyimpan hash `.text` bersih per-chunk untuk anotasi `(=disk)` / `(!disk)` saat delta.
- Auto-Whitelist Disk-Match: Jika SEMUA delta chunk cocok disk dan `INTEGRITY_AUTO_WHITELIST_DISK_MATCH_DEFAULT` true → otomatis di-whitelist + rebaseline (tanpa terminate) + telemetry counter meningkat (`awNtdll`, `awKernel32`, `awUser32`, `awGdi32`).
- HMAC Persistence (Chained): `ntdll_baseline.txt`, `kernel32_baseline.txt`, `user32_baseline.txt`, `gdi32_baseline.txt` memakai format versi 2 (lihat di atas) dengan HMAC SHA-256 dan opsional previous-chain HMAC jika `INTEGRITY_CHAIN_BASELINE_DEFAULT` aktif.
- Key Derivation Refactor: Semua modul sekarang memakai util bersama `IntegrityHmacUtil::BuildModuleKey` yang:
  1. Merakit kunci obfuscated 32-byte.
  2. Opsional XOR hash HWID (konfigurasi `INTEGRITY_HMAC_HWID_ENABLED_DEFAULT`).
  3. Diversifikasi per modul (XOR nama modul) untuk meminimalkan korelasi antar baseline.
- File Baseline: Disimpan di direktori kerja proses; mismatch HMAC → baseline diabaikan dan baseline fresh direcapture (mencegah poisoning sederhana).

Format Baseline Versi 2 (semua modul):

```text
<version> <baselineHash> <chunkCount> <chunkHashes...> <diskHash> <diskChunkCount> <diskChunkHashes...> <hmacHex> [prevHmacHex]
```

Contoh (dipotong) `kernel32_baseline.txt`:

```text
2 123456789012345 128 <...128 angka...> 987654321012345 128 <...128 angka...> a1b2c3... (64 hex) d4e5f6...(64 hex optional)
```

Telemetry Tambahan:

- Counter auto-whitelist per modul membantu audit patch OS vs anomali injeksi. Lonjakan tak biasa di satu modul → sinyal investigasi.

Policy Shortcut: `mX-Y` tetap default ke `ntdll.dll`; gunakan bentuk eksplisit (`kernel32.dll m10-12`, `user32.dll m5-9`, `gdi32.dll m3-4`) untuk modul lain.

### Auto Disk-Match Whitelist

Jika `INTEGRITY_AUTO_WHITELIST_DISK_MATCH_DEFAULT` = true, dan semua chunk yang berubah relatif terhadap baseline lama ternyata identik dengan salinan bersih di disk (`(=disk)`), maka:

1. Chunk tersebut otomatis dimasukkan ke whitelist (runtime) untuk modul terkait.
2. Baseline hash dan chunk hash diperbarui (rebaseline) tanpa men-trigger termination.
3. Log info dicetak: `auto-whitelisted disk-matching chunks`.
4. Gunakan bersama `MODSEC_AUDIT=1` untuk fase kalibrasi patch OS → aktifkan flag → jalankan game → kumpulkan log → setelah stabil simpan whitelist permanen via policy (future parser range support).

Keamanan: hanya berlaku jika SEMUA deltas bernilai `(=disk)`. Jika ada satu chunk yang tidak cocok disk (`(!disk)`), proses deteksi normal tetap berjalan.

### Whitelist Chunk Range Syntax (Policy)

Section `[chunk_whitelist]` kini mendukung variasi:

1. `ntdll.dll 12` → single chunk (format legacy tetap berlaku)
2. `ntdll.dll 12-18` → range inklusif
3. `ntdll.dll m12-18` → alternatif prefiks `m` (menegaskan “chunk”)
4. `user32.dll:m4-9` → inline modul + token `m`
5. `m10-20` → shortcut modul default `ntdll.dll` (heuristik umum patch Windows)
6. `user32.dll:m7` → single chunk via token

Catatan:

- Rentang otomatis digabung (interval merging) sehingga input tumpang tindih jadi satu interval.
- Output penyimpanan policy saat ini tetap melakukan enumerasi setiap chunk (optimisasi future: persist bentuk range).
- Batas enumerasi ekspor saat ini: maks 1024 item per interval saat serialisasi `GetAll()` (untuk mencegah dump raksasa tidak perlu).

### Audit Mode Cepat

```powershell
set MODSEC_AUDIT=1   # Windows PowerShell / CMD
```

Semua detection akan tetap dipublish (dengan label `(AUDIT)`), tetapi proses tidak diterminate. Gunakan untuk mengumpulkan delta whitelist setelah patch Windows.

### Catatan Migrasi Baseline

- File baseline lama (versi 1) otomatis di-parse dan diserialisasi ulang dalam format versi 2 saat capture baru.
- Jika HMAC mismatch pada load → baseline diabaikan dan baseline fresh ditangkap ulang.

### Rencana Lanjutan

- Policy syntax ring-kompresi whitelist (persist bentuk range langsung).
- Driver kernel: snapshot SSDT + verifikasi PEB pointer chain -> disuplai ke `KernelSurfaceStub` untuk perbandingan silang.
- Ekstensi heuristik memory: marking halaman JIT + analitik transisi proteksi.
- Replay mitigasi lanjutan: binding sequence + time window adaptif (sudah sebagian dengan SEQ + NONCE, bisa diperketat).

Roadmap Opsional:

- Negotiated capabilities line (misal `OK CAPA:HMAC,CRC`) untuk future extensibility.
- Sequence number + binding ke HMAC untuk ordering guarantee.

## Sequence Number (Ordering & Stronger Replay Guard)

Fitur ini menambahkan `|SEQ=<uint64>` pada akhir payload sebelum tag HMAC (`|H=`). Sequence dilindungi oleh HMAC sehingga tidak bisa dimodifikasi tanpa terdeteksi.

Format Wire (simplified):

```text
NONCE=aaaaaaaa; <payload_utf8>|SEQ=42|H=<sha256(sessionKey + payload_utf8|SEQ=42)>
```

Server Behavior:

1. Verifikasi HMAC (jika required / ada tag) atas string yang masih mengandung `|SEQ=...`.
2. Parse SEQ (harus segment terakhir sebelum HMAC atau akhir jika HMAC off).
3. Monotonic check:

   - Pertama: tetapkan baseline (accept).
   - `seq <= lastSeq`: drop (`[SEQFAIL][ORDER]`) bila enforcement aktif.
   - `seq == lastSeq + 1`: normal.
   - `seq > lastSeq + 1`: log gap (`[SEQGAP] expected=<last+1> got=<seq>`) dan accept.

4. Payload final untuk log dibersihkan dari `|SEQ=` (metadata internal).

Konfigurasi:

| Konstanta | Efek |
|-----------|------|
| `PIPE_SEQ_ENFORCE_DEFAULT` | True → drop out-of-order atau missing SEQ |

Deployment Notes:

- Klien lama (tanpa SEQ) akan di-drop jika enforcement aktif.
- Untuk migrasi bertahap: set `PIPE_SEQ_ENFORCE_DEFAULT=false` sementara; server hanya log `[SEQWARN]`.
- HMAC + SEQ = proteksi integritas & ordering. Nonces tetap dibutuhkan untuk replay window time-based.

Limitasi & Future:

- Tidak ada wrap handling khusus (praktis tak tercapai dalam runtime normal).
- Belum ada counter statistik gap teragregasi (bisa ditambah untuk telemetri).
- Belum ada command runtime untuk toggle SEQ enforce (mirip ide toggle HMAC).

## Replay Cache Optimization

Implementasi sebelumnya menggunakan `std::vector` dengan prune linear O(n) dan pencarian duplikat O(n). Sudah diganti menjadi kombinasi `std::deque` (menjaga urutan waktu untuk eviksi window) + `std::unordered_set` (cek keanggotaan O(1) rata-rata). Hasil:

- Insert + lookup → O(1) average.
- Prune window → loop hanya over entri expired di depan (amortized O(k) kecil).
- Capacity enforcement → while loop pop front menjaga memori stabil.

Konstanta terkait masih sama (`PIPE_REPLAY_WINDOW_MS`, `PIPE_REPLAY_CACHE_MAX`). Tidak ada perubahan format protokol.

## Runtime Configuration Commands

Server log pipe kini mendukung perintah inline (dikirim sebagai payload biasa) untuk men-toggle fitur tanpa rebuild.

Format:

```text
#SET HMACREQ=0|1
#SET SEQENFORCE=0|1
#DUMP STATE
```

Perilaku:

- Baris diawali `#SET` diproses sebelum parsing normal dan tidak dilog sebagai payload client.
- `HMACREQ` mengubah enforcement HMAC runtime (paket tanpa HMAC akan drop jika 1).
- `SEQENFORCE` mengubah enforcement sequence monotonic runtime.

Keamanan Tambahan:

- `PIPE_SET_REQUIRE_HMAC` (config compile-time) jika `true` memaksa setiap baris `#SET` hanya diterima bila paket memuat HMAC valid. Gunakan ini untuk mencegah downgrade konfigurasi oleh injeksi plaintext.

Catatan Keamanan:

- Tidak ada autentikasi tambahan; hanya gunakan di lingkungan trusted atau layer-kan ACL Named Pipe.
- Pertimbangkan menambah whitelist origin / HMAC wajib sebelum memproses `#SET` (future hardening).

Contoh:

```text
#SET HMACREQ=1
#SET SEQENFORCE=0
#DUMP STATE
```

Roadmap Opsional:

- Tambah `#SET REPLAYWINDOW=<ms>` untuk tuning dinamis.
- Komando `#DUMP STATE` memberikan snapshot HMAC/SEQ flags, lastSeq, replay cache size, dan counter setiap event (`c_<EVENT>` flatten) dalam JSON satu baris.
- Diaktifkan via `PIPE_SET_CRC_ON`; pesan memiliki suffix `|CRC=XXXXXXXX` sebelum obfuscation.

## Security Event Logging (Structured JSON)

Server kini mengemisi baris JSON satu-per-event (Line-Oriented) untuk semua kejadian keamanan kritikal / anomali protokol. Format ini memudahkan ingestion ke sistem SIEM / log aggregator tanpa perlu parsing regex rapuh atas log teks legacy.

Karakteristik:

- Satu objek JSON per line (tanpa spasi awal / indent) → aman dipipe ke collector.
- Field minimal selalu ada: `ts` (epoch ms, string), `evt` (kode event), `v` (versi schema saat ini `1`).
- Field tambahan (key/value) hanya muncul jika relevan (schema forward-compatible: jangan hard-fail bila menemukan field baru).
- Semua nilai direpresentasikan sebagai string untuk kesederhanaan (hindari masalah tipe lintas bahasa ingestion awal).

Contoh (diringkas, wrapping manual hanya dokumentasi – implementasi real: satu line):

```text
{"ts":"1726423456789","evt":"HANDSHAKE_FAIL","reason":"TIMEOUT_HELLO","v":1}
{"ts":"1726423456791","evt":"HANDSHAKE_OK","hmacRequired":"1","v":1}
{"ts":"1726423456890","evt":"REPLAY_DROP","nonce":"7fa3bc21","v":1}
{"ts":"1726423457002","evt":"HMAC_FAIL","crcOk":"1","v":1}
{"ts":"1726423457010","evt":"SEQ_FAIL","type":"ORDER","seq":"105","last":"110","v":1}
{"ts":"1726423457022","evt":"SEQ_GAP","expected":"210","got":"214","v":1}
{"ts":"1726423457100","evt":"CFG_SET","key":"HMACREQ","value":"1","v":1}
{"ts":"1726423457105","evt":"CFG_DENY","reason":"NO_HMAC","key":"SEQENFORCE","v":1}
{"ts":"1726423457110","evt":"CFG_UNKNOWN","key":"FOO","v":1}
```

### Daftar Event & Field Khusus

| Event | Deskripsi | Field Tambahan |
|-------|-----------|----------------|
| `HANDSHAKE_FAIL` | Handshake gagal (fase HELLO / AUTH) | `reason` (`TIMEOUT_HELLO` / `BAD_AUTH_FORMAT` / `BAD_DIGEST`) |
| `HANDSHAKE_OK` | Handshake sukses | `hmacRequired` (`1/0`) |
| `REPLAY_DROP` | Paket ditolak karena nonce sudah pernah diterima dalam window | `nonce` (hex, lower) |
| `HMAC_FAIL` | Verifikasi HMAC gagal (mismatch) | `crcOk` (`1/0`) menandai apakah CRC (jika ada) lolos |
| `SEQ_FAIL` | Sequence error dan paket di-drop (enforce aktif) | `type` (`ORDER`/`MISSING`/`ABSENT`), `seq`, `last` (hanya ORDER) |
| `SEQ_WARN` | Sequence anomali tapi tidak di-drop (enforce off) | `type`, `seq`, `last` (conditional) |
| `SEQ_GAP` | Diterima dengan gap (seq > last+1) | `expected`, `got` |
| `CFG_SET` | Runtime config `#SET` diterapkan | `key`, `value` |
| `CFG_DENY` | `#SET` ditolak (biasanya karena tidak ada HMAC) | `reason` (`NO_HMAC`), `key` |
| `CFG_UNKNOWN` | `#SET` dengan key tak dikenali | `key` |

Catatan Sequence:

- `SEQ_FAIL` tipe `ORDER`: `seq <= lastSeq` (rewind / duplikat)
- `SEQ_FAIL` tipe `MISSING`: Tag `|SEQ=` hilang pada paket yang seharusnya memilikinya
- `SEQ_FAIL` tipe `ABSENT`: Paket sama sekali tanpa field sequence saat enforcement aktif
- `SEQ_GAP` diterbitkan terpisah meskipun paket diterima (observabilitas gap vs rewind)

### Konsumsi & Integrasi

Langkah umum ingestion:

1. Baca stdout/stderr server → filter baris yang dimulai `{"ts":` (atau parse penuh JSON line-based).
2. Normalisasi: convert string numerik ke tipe asli bila diperlukan (timestamp, seq).
3. Index dengan key `evt` untuk query cepat (contoh di Elastic / Loki / Splunk).
4. Tambah pipeline rule: alert jika `HMAC_FAIL` > N dalam window pendek atau ada `HANDSHAKE_FAIL` berurutan > M.

### Garansi Stabilitas Awal

- Versi schema awal: `v=1`. Penambahan field baru tidak akan mengubah arti field lama.
- Perubahan nama event akan melalui penambahan alias transisi (misal `evt2`) – belum direncanakan dalam waktu dekat.

### Roadmap Structured Logging

| Tahap | Fitur | Status |
|-------|-------|--------|
| 1 | Emisi event protokol dasar (handshake, replay, hmac, seq, cfg) | Selesai |
| 2 | Counter agregasi & `#DUMP STATE` (JSON snapshot) | Selesai |
| 3 | Rate limit / sampling event banjir (misal `HMAC_FAIL`) | Planned |
| 4 | Sink file rotasi (`security_events.log` + size/time rotate) | Planned |
| 5 | Ekspor opsional ke TCP/UDP syslog / webhook | Exploratory |
| 6 | Penandaan sesi (session id) di setiap event | Planned |

### Best Practice Operasional

- Simpan raw events minimal 7 hari untuk forensik replay / ordering.
- Monitor anomali burst `REPLAY_DROP` (indikasi brute-force nonce / injeksi ulang payload).
- `CFG_DENY` berulang bisa menandakan probing downgrade oleh proses tidak authorized.
- Aktifkan `PIPE_SET_REQUIRE_HMAC` untuk menutup vektor downgrade `HMACREQ`.

### Contoh Parser Sederhana (Pseudo Python)

```python
import json, sys
for line in sys.stdin:
  if not line.startswith('{"ts"'):
    continue
  try:
    evt = json.loads(line)
  except json.JSONDecodeError:
    continue
  if evt.get('evt') == 'HMAC_FAIL':
    # increment metric / alert
    pass
```

Dengan struktur ini Anda dapat menambah pipeline analytics tanpa perlu memodifikasi kode C++ inti saat menambah tipe event baru.

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
- Handshake autentikasi pipe (baru) mengurangi risiko spoof command / sniff sederhana.

### Handshake Autentikasi Pipe (Baru 2025-09)

Untuk menghindari proses asing langsung mengirim command atau membaca log, channel pipe sekarang mendukung handshake ringan berbasis shared key dan nonce:

Alur (client → server command pipe):

1. Client membuka pipe dan mengirim: `HELLO <nonceCliHex>` (`nonceCli` derivatif dari `GetTickCount64()` + pointer internal)
2. Server membalas: `CHALLENGE <nonceSrvHex>` (`nonceSrv` campuran tick + handle pointer)
3. Client menghitung: `digest = SHA256( keyUtf8 + nonceCliHex + nonceSrvHex )` (hex lower-case 64 char) dan mengirim: `AUTH <digest>`
4. Server validasi digest; jika cocok → `OK`, jika tidak → `FAIL` dan koneksi ditutup.

Setelah `OK`, client baru mengirim paket log normal (`NONCE=...;...`). Sebelum autentikasi selesai, queue pesan ditahan (tidak dikirim).

Fallback Legacy: (DINONAKTIFKAN DEFAULT) Sebelumnya, jika server menerima line pertama bukan `HELLO`, ia menganggap client lama dan langsung memproses line itu tanpa autentikasi. Sekarang strict default aktif (`PIPE_HANDSHAKE_STRICT_DEFAULT = true`), koneksi tanpa `HELLO` langsung ditolak. Aktifkan kembali mode lama hanya jika perlu rollback cepat dengan mengubah konstanta / command runtime (jika disediakan).

Shared Key Runtime:

- Nilai awal diambil dari `Config::PIPE_SHARED_KEY` saat start.
- Dapat diganti runtime melalui command baru: `PIPE_SET_SHARED_KEY <plain_utf8_key>` (tidak disimpan ke policy; rotasi ephemeral).
- Manajer: `SharedKeyManager` menyimpan key dalam UTF-8 (mutex-protected) dipakai saat menghitung digest handshake.

Pertimbangan Keamanan Tambahan:

- Gunakan ACL/SDDL pada named pipe di server final untuk membatasi siapa bisa connect (handshake bukan substitusi penuh ACL).
- Ganti RNG nonce menjadi `BCryptGenRandom` untuk entropi lebih kuat bila diperlukan.
- Tambahkan rate limit terhadap kegagalan handshake (drop setelah N gagal berturut dalam window pendek).
- Pertimbangkan HMAC per pesan (misal `|H=<sha256(key+payload)>`) jika channel dianggap hostile.

Command Baru:

```text
PIPE_SET_SHARED_KEY <key_utf8>
PIPE_HANDSHAKE_STRICT_ON
PIPE_HANDSHAKE_STRICT_OFF
PIPE_HMAC_ON
PIPE_HMAC_OFF
```

Respon: `INFO|RESULT|PIPE_SET_SHARED_KEY OK` bila sukses.

Catatan Implementasi:

- Digest diserialisasi hex lower-case.
- Key kosong diabaikan (tidak mereset ke string kosong untuk mencegah degradasi keamanan tidak sengaja).
- Handshake timeout: `PIPE_HANDSHAKE_TIMEOUT_MS` (default 3000 ms) untuk masing-masing fase baca.
- Jika handshake gagal: server kirim `FAIL`, menutup handle; client menutup pipe dan retry setelah `PIPE_RECONNECT_MS`.

Fitur Tambahan Baru:

- Strict mode (`PIPE_HANDSHAKE_STRICT_ON`): menolak klien tanpa `HELLO`. SEKARANG DEFAULT ON (`PIPE_HANDSHAKE_STRICT_DEFAULT = true`), sehingga fallback legacy non-handshake tidak diterima kecuali Anda override.
- Rate limiting gagal handshake: dalam window `PIPE_HANDSHAKE_FAIL_WINDOW_MS` jika gagal ≥ `PIPE_HANDSHAKE_FAIL_MAX`, penalti sleep `PIPE_HANDSHAKE_PENALTY_MS` diterapkan sebelum menerima koneksi baru (memperlambat brute-force digest).
- RNG nonce memakai `BCryptGenRandom` (fallback ke kombinasi tick+pointer bila gagal) di kedua sisi (client & server) untuk meningkatkan entropi.
- HMAC payload opsional: bila diaktifkan (`PIPE_HMAC_ON`), setiap payload log sebelum CRC/XOR ditambahkan suffix `|H=<sha256(key+payload_plain)>`. Verifikasi sisi server saat ini belum diterapkan (mode satu arah untuk anti-tamper ringan). Aktifkan setelah memastikan panjang pesan tidak melebihi batas pipeline parsing Anda.
- Migrasi hashing internal dari CryptoAPI (Wincrypt) ke CNG (`BCrypt*`) untuk konsistensi modern, mengurangi overhead context acquire per hash, dan mempermudah adopsi algoritma lanjutan (misal SHA-512 atau KDF) tanpa refactor besar.

Format Paket Saat HMAC Aktif:

```text
NONCE=xxxxxxxx;NONCRC|FIELD1|FIELD2|...|H=64hex[|CRC=XXXXXXXX]
```

Urutan Transformasi:

1. Bangun payload log dasar (sudah disanitasi)
2. (Opsional) Tambah `|H=` jika HMAC ON
3. (Opsional) Tambah `|CRC=` jika CRC ON
4. (Opsional) Rolling XOR seluruh bagian setelah header `NONCE=...;`

Verifikasi Server (Future Work):

- Tambah parsing trailing `|H=` setelah de-obfuscate & sebelum gunakan isi.
- Validasi dengan key runtime; mismatch → drop / flag tamper.
(Update 2025-09-16) Implementasi dasar verifikasi HMAC server sudah ditambahkan di `PipeServer.cpp` dengan fallback langsung memakai shared key (belum derivasi session nonce). Jika `|H=` ada, server recompute `sha256(key+payload_without_H)` dan drop bila mismatch.
Flag baru `PIPE_HMAC_REQUIRED_DEFAULT` disiapkan di `Config.h` (sisi client) untuk memudahkan enforce mode; saat ini server contoh masih `hmacRequired=false` (hard-coded) — ubah sesuai kebutuhan operasi.
Tahap berikut: derivasi session key: `sessionKey = SHA256(sharedKeyUtf8 + nonceCliHex + nonceSrvHex)` dipakai untuk HMAC sehingga shared key statis tidak langsung terekspos via analisis pola.
Replay guard (nonce) telah ditambahkan di server contoh: setiap `nonce` (8 hex dari header `NONCE=`) dilacak dalam window `PIPE_REPLAY_WINDOW_MS` dengan batas cache `PIPE_REPLAY_CACHE_MAX`; duplikat dalam window ditandai `[REPLAY]` dan dibuang.
Session Key (Log Channel): Server melakukan handshake HELLO/CHALLENGE/AUTH untuk channel log (bukan hanya command). Setelah validasi digest (`SHA256(sharedKey + nonceCli + nonceSrv)`), diturunkan `sessionKey = SHA256(sharedKey + nonceCli + nonceSrv)` yang digunakan menggantikan shared key dasar saat verifikasi HMAC payload. Legacy klien tanpa HELLO TIDAK lagi diterima karena strict default aktif.

Parameter Baru di `Config.h`:

| Konstanta | Deskripsi |
|-----------|-----------|
| `PIPE_HANDSHAKE_STRICT_DEFAULT` | Default strict mode (false = masih izinkan legacy) |
| `PIPE_HANDSHAKE_FAIL_WINDOW_MS` | Window perhitungan gagal handshake |
| `PIPE_HANDSHAKE_FAIL_MAX` | Ambang gagal sebelum penalti |
| `PIPE_HANDSHAKE_PENALTY_MS` | Lama penalti sleep tambahan |
| `PIPE_HMAC_DEFAULT_ENABLED` | HMAC payload aktif (default false) |
| `PIPE_HMAC_REQUIRED_DEFAULT` | Server mewajibkan HMAC (default false) |
| `PIPE_REPLAY_WINDOW_MS` | Window waktu nonce dianggap valid untuk anti-replay |
| `PIPE_REPLAY_CACHE_MAX` | Maksimum entri cache nonce sebelum eviksi sederhana |

Roadmap Opsional:

- Komando persist key ke policy terenkripsi (belum ada).
- Strict mode: tolak legacy tanpa HELLO.
- Replay guard: cache pasangan nonce (client+server) untuk mencegah reuse dalam window singkat.
- Penggabungan digest handshake ke header paket (nonce+HMAC) agar setiap pesan terikat pada sesi.

## Session ID (2025-09)

Setiap sesi pipe sekarang diberi `sessionId` 128-bit (hex) yang dihasilkan secara kriptografis pada saat handshake sukses.

Karakteristik:

- Format: 32 hex lowercase (128-bit RNG via `BCryptGenRandom`, fallback entropy jika gagal).
- Dikirim ke klien di baris handshake: `OK HMAC SESSIONID=<hex>` atau `OK SESSIONID=<hex>`.
- Otomatis ditambahkan ke setiap event JSON `SecEvent` sebagai field: `"sessionId":"<hex>"` (kecuali sebelum handshake selesai / legacy path).
- Muncul di output `#DUMP STATE` (`evt":"STATE"`) untuk korelasi alat observasi.
- Tidak digunakan sebagai key kriptografi; murni identitas korelasi / forensic timeline.

Manfaat:

## Integrity Control-Plane Commands (Runtime Telemetry & Maintenance)

Empat modul inti OS yang dimonitor (`ntdll.dll`, `kernel32.dll`, `user32.dll`, `gdi32.dll`) kini memiliki command operasi untuk inspeksi status integritas, rebaseline manual, dan verifikasi on-demand tanpa menunggu interval scheduler.

### Ringkasan Command

| Command | Deskripsi | Argumen | Output Utama |
|---------|-----------|---------|--------------|
| `INTEGRITY_STATUS` | Status ringkas seluruh modul (plain text) | - | Line tunggal per semua modul disatukan |
| `INTEGRITY_STATUS_JSON` | Status terstruktur (JSON satu line) | - | Objek JSON berisi 4 key modul |
| `INTEGRITY_REBASELINE <mod\|ALL>` | Paksa tangkap baseline baru (manual) | Nama modul atau ALL | `RESULT` per modul OK/FAIL |
| `INTEGRITY_VERIFY <mod\|ALL>` | Hash `.text` saat ini vs baseline (tanpa rebaseline) | Nama modul atau ALL | `RESULT` per modul OK/FAIL |

Modul bisa disebut dengan / tanpa `.dll` (otomatis ditambah). `ALL` menjalankan perintah keempat modul berurutan.

### Field Telemetry per Modul

Field yang diekspor di `INTEGRITY_STATUS_JSON` (semua numerik kecuali timestamp):

| Field | Arti |
|-------|------|
| `baselineLoadsOk` | Jumlah load / capture baseline sukses (persisted atau fresh) |
| `hmacMismatch` | Baseline dibuang karena HMAC tidak cocok (indikasi tamper) |
| `rebaselineCount` | Total baseline baru (manual + auto whitelist) |
| `manualRebaselineCount` | Subset rebaseline yang dipicu operator (`INTEGRITY_REBASELINE`) |
| `chainAdvanceCount` | Jumlah kali HMAC lama dipindah ke rantai (chained baseline) |
| `autoWhitelistCount` | Auto rebaseline karena seluruh delta chunk = disk bersih |
| `verifyNowRequests` | Panggilan `INTEGRITY_VERIFY` |
| `forceVerifyFailures` | Verifikasi on-demand gagal (mismatch) |
| `totalChunks` | Jumlah chunk `.text` pada baseline terbaru |
| `whitelistedChunks` | Snapshot banyak chunk di whitelist runtime |
| `hmacValid` | 1 bila baseline aktif lulus verifikasi HMAC |
| `chainDepth` | Panjang rantai HMAC (1 = hanya current, 2 = current+prev) |
| `lastBaselineTime` | ISO8601 UTC baseline / rebaseline terakhir (manual / auto) |
| `lastAutoWhitelistTime` | Waktu terakhir auto-whitelist rebaseline |
| `lastManualRebaselineTime` | Waktu terakhir perintah manual rebaseline |

Nilai timestamp bisa kosong (`""`) bila belum pernah terjadi event terkait.

### Contoh Output

Plain text (`INTEGRITY_STATUS`):

```text
ntdll.dll bl=3 hm=0 rb=2 (man=1) aw=1 vfy=4 vfFail=0 wl=12/128 hmac=OK chain=2 | kernel32.dll bl=3 hm=0 rb=1 (man=0) aw=1 vfy=2 vfFail=0 wl=5/96 hmac=OK chain=1 | user32.dll bl=2 hm=0 rb=1 (man=1) aw=0 vfy=1 vfFail=0 wl=0/110 hmac=OK chain=1 | gdi32.dll bl=2 hm=0 rb=1 (man=0) aw=1 vfy=1 vfFail=0 wl=0/104 hmac=OK chain=1
```

JSON (`INTEGRITY_STATUS_JSON` diringkas, satu line real):

```json
{"ntdll.dll":{"baselineLoadsOk":3,"hmacMismatch":0,"rebaselineCount":2,"manualRebaselineCount":1,"chainAdvanceCount":1,"autoWhitelistCount":1,"verifyNowRequests":4,"forceVerifyFailures":0,"totalChunks":128,"whitelistedChunks":12,"hmacValid":1,"chainDepth":2,"lastBaselineTime":"2025-09-16T12:34:10Z","lastAutoWhitelistTime":"2025-09-16T12:33:50Z","lastManualRebaselineTime":"2025-09-16T12:34:10Z"},"kernel32.dll":{...},"user32.dll":{...},"gdi32.dll":{...}}
```

### Rebaseline Manual vs Auto-Whitelist

- Manual (`INTEGRITY_REBASELINE`) selalu meningkatkan `manualRebaselineCount` dan mengisi `lastManualRebaselineTime`.
- Auto rebaseline hanya terjadi jika SEMUA delta chunk yang bukan whitelist cocok dengan hash chunk disk `(=disk)`. Jika satu saja `(!disk)`, proses detection normal (exit) berjalan.
- Keduanya meningkatkan `rebaselineCount` dan memperbarui `lastBaselineTime`.

### Chained Baseline

Jika `INTEGRITY_CHAIN_BASELINE_DEFAULT` aktif dan baseline lama memiliki HMAC valid, HMAC lama disalin sebagai `prevChain` saat baseline baru dibuat. Ini menambah lineage sehingga injeksi baseline baru tanpa jejak lebih sulit.

`chainDepth` = 1 berarti hanya baseline aktif; =2 berarti baseline saat ini + satu link sebelumnya (implementasi saat ini tidak menyimpan lebih dari 1 link historis untuk footprint ringkas).

### Verifikasi On-Demand

`INTEGRITY_VERIFY <mod>` menghitung hash `.text` modul saat ini dan membandingkan dengan baseline tanpa memicu rebaseline. Kegagalan (mismatch) menambah `forceVerifyFailures` (indikasi potensi racing patch / injeksi) – keputusan lanjutan (terminate / escalate) dapat dihubungkan ke pipeline detection lain.

### Pola Operasional Disarankan

1. Setelah patch Windows → jalankan klien dengan `MODSEC_AUDIT=1` beberapa menit.
2. Pantau `INTEGRITY_STATUS_JSON` untuk modul dengan `autoWhitelistCount` bertambah.
3. Review delta log awal (jika ada) → persist whitelist range ke policy permanen bila stabil.
4. Jalankan `INTEGRITY_REBASELINE ALL` untuk menutup chain dan memperbarui timestamp.
5. Kembali ke mode normal (tanpa `MODSEC_AUDIT`).

### Failure Handling & Hints

- `hmacMismatch > 0` segera investigasi: baseline file bisa rusak / dimodifikasi.
- `forceVerifyFailures` bertambah tanpa rebaseline sah → indikator race benign vs malicious patch; pertimbangkan memperketat interval check atau escalate ke kill.
- `whitelistedChunks/totalChunks` terlalu besar (misal >25%) → evaluasi ulang whitelist; potensi over-whitelisting menurunkan sensitivitas.

### Keamanan

- Jangan jalankan `INTEGRITY_REBASELINE` sembarang di environment produksi tanpa audit log; baseline poisoning bisa menyembunyikan patch injeksi sementara.
- Gunakan chaining + HMAC HWID untuk mitigasi baseline copy-replay antar mesin.

### Roadmap Integrity Control-Plane

| Item | Status | Catatan |
|------|--------|---------|
| Export manual rebaseline reason | Planned | Argumen opsional di command |
| Multi-link chain >2 | Planned | Perlu format baseline v3 |
| Policy persist baseline HMAC | Exploratory | Untuk offline attestation |
| Server side integrity mirror | Planned | Kirim status periodik ke server pusat |
| Built-in telemetry export (TCP) | Selesai (basic) | `INTSTAT\|{...}` push via TcpClient |

Dengan command ini operasional anti-cheat dapat melakukan inspeksi cepat & tindakan korektif tanpa rebuild / redeploy.

### Telemetry Export (Central Server Push)

Fitur opsional untuk mengirim snapshot JSON integritas ke server pusat secara periodik memakai koneksi TCP bawaan (`TcpClient`).

Format frame terbaru (sementara plaintext):

```text
INTSTAT|sid=<32hex>|seq=<n>|{jsonSnapshot}[|X=<hmacHex64>|ALG=hmac256]\n
```

Keterangan:

- `sid` : 128-bit random (hex 32) di-generate sekali per sesi eksport.
- `seq` : counter increment per frame (mulai dari 1). Dipakai server untuk deteksi out-of-order / replay.
- Bagian JSON sama dengan output `INTEGRITY_STATUS_JSON` (empat modul sebagai key).
- HMAC opsional: `X=` berisi HMAC-SHA256 (64 lowercase hex) atas seluruh payload sebelum `|X=` (termasuk sid & seq). Tag algoritma saat ini `ALG=hmac256`.

Aktivasi Runtime:

```text
INTEGRITY_EXPORT_ON
INTEGRITY_EXPORT_INTERVAL 15000   # ms
INTEGRITY_EXPORT_NOW              # push segera (tidak mempengaruhi jadwal berikutnya)
INTEGRITY_EXPORT_OFF
INTEGRITY_EXPORT_STATUS           # tampilkan state & interval
TCP_CLIENT_START 203.0.113.10 9000
TCP_CLIENT_STOP
```

Konstanta:

| Konstanta | Default | Deskripsi |
|-----------|---------|-----------|
| `INTEGRITY_EXPORT_ENABLED_DEFAULT` | false | Auto aktif awal jika true |
| `INTEGRITY_EXPORT_INTERVAL_MS_DEFAULT` | 15000 | Interval push default (ms) |
| `INTEGRITY_EXPORT_MAX_JSON` | 2048 | Batas panjang snapshot dipotong |
| `INTEGRITY_EXPORT_HMAC_ENABLED_DEFAULT` | false | Aktifkan penambahan `\|X=<hmac64>\|ALG=hmac256` |
| `INTEGRITY_EXPORT_HMAC_REQUIRE_DEFAULT` | false | Wajibkan frame memiliki `\|X=` (kalau gagal generate: frame dibatalkan) |
| `INTEGRITY_EXPORT_TLS_ENABLED_DEFAULT` | false | Placeholder untuk future TLS |

Catatan Implementasi:

- Adapter detector `IntegrityExport` di scheduler memanggil `Tick()` tiap 1s; hanya mengirim bila interval terlampaui & fitur enabled.
- JSON isi identik struktur dengan `INTEGRITY_STATUS_JSON` (field sama) sehingga backend bisa reuse parser.
- Payload dipotong bila melebihi batas (fail-safe agar tidak flood karena bug penambahan field besar).
- Koneksi TCP harus sudah diinisialisasi via `TcpClient::Start()` (pastikan host/port dipanggil dari integrasi Anda—placeholder belum ditambahkan per sample ini bila host dinamis).

Integrasi Backend:

1. Listeni newline-delimited frames.
2. Filter prefix `INTSTAT|` (abaikan baris lain seperti log biasa).
3. Parse sisa sebagai JSON; index per modul.
4. Alert jika `hmacMismatch > 0` atau lonjakan tiba-tiba `autoWhitelistCount`.

Roadmap Lanjutan (update):

| Fitur | Status | Catatan |
|-------|--------|---------|
| Transport control via commands | Selesai | START/STOP, interval, status |
| HMAC-SHA256 envelope | Selesai | CNG HMAC 64 hex + ALG tag |
| Session id + sequence | Selesai | Anti replay / korelasi server |
| Key rotation manual & interval | Selesai | Random 32B → hex 64 |
| TLS / mTLS koneksi telemetry | Skeleton | Abstraksi siap (transport interface) |
| Delta-only snapshot | Planned | Optimisasi bandwidth |
| Buffering offline & resend | Planned | Saat koneksi drop |
| Compression (opsional) | Planned | Setelah TLS (negotiation) |
| Server side anomaly scoring | Planned | Sequence gap / hmac fail weighting |
| Multi-endpoint failover | Planned | Redundansi collector |

#### HMAC Envelope

Implementasi saat ini: HMAC-SHA256 (Windows CNG) atas substring sebelum `|X=` (seluruh header + JSON). Hasil 32 byte → 64 hex lowercase.

Fallback: Jika HMAC gagal (misal CNG error) dan `require=OFF`, akan fallback ke truncated hash lemah dengan `ALG=weak`. Jika `require=ON`, frame dibatalkan dan error di-log.

Contoh frame:

```text
INTSTAT|sid=3e7f4a2d9b6c412e8d90bc7711fa55d1|seq=5|{"ntdll.dll":{"baselineLoadsOk":1,...}}|X=2f0d9a2a...c5d0|ALG=hmac256
```

Runtime Commands (export & security):

```text
INTEGRITY_EXPORT_ON
INTEGRITY_EXPORT_OFF
INTEGRITY_EXPORT_INTERVAL <ms>
INTEGRITY_EXPORT_NOW
INTEGRITY_EXPORT_STATUS                # tampilkan interval, hmac on/off, require, rotasi
INTEGRITY_EXPORT_SET_KEY <utf8_key>    # set manual key (plaintext utf8)
INTEGRITY_EXPORT_ROTATE_KEY            # generate random 32B → hex 64 dan pakai segera
INTEGRITY_EXPORT_ROTATE_INTERVAL <ms>  # auto-rotate periodik (>=1000ms; 0 untuk off)
INTEGRITY_EXPORT_HMAC_ON / OFF
INTEGRITY_EXPORT_HMAC_REQUIRE_ON / OFF
INTEGRITY_EXPORT_TLS_ON / OFF          # skeleton (belum enkripsi)
TCP_CLIENT_START <host> <port>
TCP_CLIENT_STOP
```

#### Contoh Server Referensi

File: `server_example/TelemetryServer.cpp`

Build cepat (Developer Command Prompt VS / x64 Native Tools):

```powershell
cl /EHsc server_example\TelemetryServer.cpp /Fe:TelemetryServer.exe ws2_32.lib
```

Jalankan:

```powershell
TelemetryServer.exe 0.0.0.0 9000 SECRET_KEY_123
```

Server (versi baru) akan log: `sid=<sid> seq=<n> hmac=OK alg=hmac256 order=OK drops=0 raw=<frame>`.

Deteksi server:

- `hmac=FAIL` → potensi manipulasi / key mismatch / replay modifikasi.
- `order=OUT` → out-of-order atau replay (cek `drops` counter per sid).
- Gap besar seq → kehilangan frame (network loss) atau filtering.

Rekomendasi manajemen key:

- Set key awal via pipeline command setelah koneksi aman.
- Aktifkan rotasi interval (misal 300000 ms = 5 menit) bila overhead koordinasi server siap.
- Sinkronisasi key ke server: gunakan channel terpisah (pipe) atau protokol TLS dengan rekey handshake (belum diimplement di sample).

#### TLS Skeleton

Saat ini hanya ada abstraksi transport (`ITelemetryTransport`) + implementasi `PlainTelemetryTransport`. Command `INTEGRITY_EXPORT_TLS_ON` hanya men-set flag (belum mengganti transport). Langkah lanjutan:

1. Tambah kelas `TlsTelemetryTransport` (Schannel) dengan state credential + context.
2. Ganti pointer transport di `TcpClient` saat `UseTls(true)` sebelum koneksi.
3. Validasi sertifikat: pin public key hash SHA-256 atau CA internal.
4. (Opsional) mutual TLS: server validasi client cert untuk anti impersonation.
5. Rekey periodik / session ticket reuse (optimisasi handshake).




- Korelasi multi-log (server console, collector eksternal) ke satu sesi koneksi.
- Investigasi insiden (misal banyak `HMAC_FAIL` → tahu sesi mana tanpa perlu hashing ulang nonce).

Catatan: event handshake / state JSON belum diimplement karena plaintext; akan relevan setelah TLS & kontrol reliabilitas ditambah.

Integrasi Klien:

- Simpan `sessionId` pada penerimaan handshake untuk tagging log lokal atau channel lain.
- (Opsional) kirim ulang di jalur command terpisah untuk audit silang.

Keamanan:

- Tidak rahasia; jangan gunakan menggantikan token auth.
- Jangan masukkan ke HMAC source kecuali ingin mengikat payload ke sesi secara eksplisit (dapat ditambahkan di fase lanjutan).

Langkah Lanjut Potensial:

- Rotasi sessionId jika inactivity > X atau setelah N pesan.
- Tambah event `SESSION_ROTATE`.
- Tambah rate-limit keyed by sessionId.

## Security Event Rate Limiting (2025-09)

Untuk mencegah banjir log saat kondisi abnormal (misal banyak paket invalid atau replay), sistem menambahkan rate limiting pada subset event keamanan.

Event yang Saat Ini Di-rate-limit:

- `HMAC_FAIL`
- `REPLAY_DROP`
- `SEQ_FAIL`
- `SEQ_WARN`
- `SEQ_GAP`

Algoritma:

- Sliding window durasi `SEC_EVT_RATE_WINDOW_MS` (default 5000 ms) per jenis event.
- Jika jumlah event dalam window melewati `SEC_EVT_RATE_THRESHOLD` (default 25) → mode suppress aktif untuk jenis itu.
- Saat suppress aktif, event asli dibuang (tidak dicetak) dan counter suppressed bertambah.
- Ketika jumlah dalam window turun <= (threshold * `SEC_EVT_RATE_RESUME_PCT` / 100) → sistem mengeluarkan ringkasan dan keluar dari suppress mode.

Event Tambahan yang Dihasilkan:

- `RATE_SUPPRESS_START` : menandakan mulai menahan jenis event target.
- `RATE_SUPPRESS_SUMMARY`: ringkasan jumlah event yang ditahan selama fase suppress.

Contoh (disederhanakan):

```json
{"evt":"RATE_SUPPRESS_START","tick":123456,"sessionId":"...","target":"HMAC_FAIL","countWindow":"26"}
{"evt":"RATE_SUPPRESS_SUMMARY","tick":123980,"sessionId":"...","target":"HMAC_FAIL","suppressed":"340"}
```

Konfigurasi (di `Config.h`):

| Konstanta | Deskripsi |
|-----------|----------|
| `SEC_EVT_RATE_WINDOW_MS` | Panjang window sliding (ms) |
| `SEC_EVT_RATE_THRESHOLD` | Ambang jumlah event sebelum suppression mulai |
| `SEC_EVT_RATE_RESUME_PCT` | Persentase ambang turun untuk keluar suppression |

### STATE Dump Augmentasi (Rate Limiting)

`#DUMP STATE` kini menyertakan snapshot ringkas status rate limiting:

- `rl_active` : Jumlah event type yang saat ini berada dalam fase suppression.
- `rl` : Array objek per event yang pernah muncul sejak start (atau sejak pertama kali event muncul) dengan kolom:
  - `evt` : Nama event (disanitasi, hanya alnum + `_`).
  - `suppress` : `1` jika sedang suppress, else `0`.
  - `window` : Jumlah event yang masih berada dalam sliding window (ukuran deque stempel waktu).
  - `suppressed` : Jumlah event yang telah ditahan selama fase suppress aktif sekarang (reset ke 0 saat suppression berakhir atau belum pernah suppress).

Contoh potongan STATE (dipadatkan):

```json
{"evt":"STATE","tick":1300455,"sessionId":"9f2c...1130","hmacRequired":"1","seqEnforce":"1","hasSeqBaseline":"1","lastSeq":"42","replayCache":"5","c_HANDSHAKE_OK":"1","c_STATE_DUMP":"2","rl_active":"1","rl":[{"evt":"HMAC_FAIL","suppress":"1","window":"37","suppressed":"12"},{"evt":"SEQ_WARN","suppress":"0","window":"3","suppressed":"0"}]}
```

Catatan:

- Event type hanya muncul di array setelah minimal satu kejadian tercatat.
- `window` bisa lebih kecil dari total kumulatif karena entri lama keluar dari sliding window.
- `suppressed` hanya meningkat selama `suppress=1`.
- Setelah suppression berakhir dan bucket kembali normal, `suppressed` reset ke `0` pada snapshot berikutnya.
- `totalSupp` adalah total kumulatif suppressed sejak start (tidak direset ketika fase suppression berakhir, hanya reset oleh RLRESET).

### Runtime Tuning Rate Limiting

Selama koneksi aktif (dan melewati syarat HMAC bila diaktifkan), server mendukung penyesuaian parameter rate limit tanpa restart melalui `#SET`:

- `#SET RTHRESH=<N>` : Ubah ambang jumlah event sebelum suppression. Valid 1 .. 100000.
- `#SET RWINMS=<MS>` : Ubah panjang window sliding (ms). Valid 100 .. 600000.
- `#SET RRESUME=<PCT>` : Ubah persentase threshold untuk resume (resume ketika jumlah dalam window <= (threshold * pct / 100)). Valid 1 .. 99.
- `#SET RLRESET=1` : Reset seluruh bucket rate limiting (menghapus histori window dan suppression counters).

Setiap perubahan menghasilkan event `CFG_SET` dengan `key` salah satu dari `RTHRESH|RWINMS|RRESUME`.
Jika nilai tidak valid → `CFG_DENY` dengan `reason=RANGE`.

STATE kini juga mengekspor 3 field konfigurasi terkini:

- `rl_thr` : Threshold aktif sekarang.
- `rl_win` : Window ms aktif sekarang.
- `rl_resume` : Persentase resume aktif sekarang.

Contoh modifikasi runtime:

```bash
#SET RTHRESH=40|H=<hmac>
#SET RWINMS=8000|H=<hmac>
#SET RRESUME=70|H=<hmac>
#DUMP STATE|H=<hmac>
```

Cuplikan STATE setelah perubahan (disingkat):

```json
{"evt":"STATE","rl_thr":"40","rl_win":"8000","rl_resume":"70", ... }
```

### Reset & Event Tambahan

Perintah `RLRESET` ketika dieksekusi akan:

- Menghapus semua bucket (histori window & status suppression).
- Menghasilkan event `RATE_RESET` dengan field:
  - `buckets` : jumlah bucket sebelum dihapus.
  - `totalSupp` : akumulasi suppressed (lifetime) semua bucket sebelum reset.

Contoh event:

```json
{"evt":"RATE_RESET","tick":1310001,"buckets":"2","totalSupp":"352"}
```

## Persistent Security Event Log (2025-09)

Fitur ini (opsional) menulis setiap baris JSON `SecEvent` ke file `.jsonl` dengan rotasi berbasis ukuran untuk forensic / post-mortem analisis.

Status default: non-aktif (`LOG_EVENT_PERSIST_ENABLED_DEFAULT=false`). Aktifkan runtime via:

```bash
#SET LOGPERSIST=1|H=<hmac>
```

Nonaktifkan kembali:

```bash
#SET LOGPERSIST=0|H=<hmac>
```

### File & Rotasi

- Basename: `SecEvents` (konfigurasi: `LOG_EVENT_FILE_BASENAME`).
- Format file: `SecEvents.<N>.jsonl` (ring index 0 .. `LOG_EVENT_MAX_ROTATIONS-1`).
- Ukuran max per file: `LOG_EVENT_MAX_BYTES` (default 524288 bytes ≈ 512 KB).
- Setelah melewati batas, indeks maju (mod rotasi) dan file baru di-truncate.
- Share mode read diizinkan untuk kolektor eksternal tailing.

### Integrasi STATE

- Field `logPersist`: `"1"` jika mode persist aktif, else `"0"`.

### Event & Audit

- Perubahan status menghasilkan `CFG_SET` dengan `key=LOGPERSIST`.
- File rotasi sendiri tidak memicu event tambahan (sederhana / low noise). Bisa ditambah di masa depan (misal `LOG_ROTATE`).

### Contoh Alur

1. Aktifkan: `#SET LOGPERSIST=1|H=<hmac>` → muncul event `CFG_SET`.
2. Jalankan beban / serangan simulasi → file `SecEvents.0.jsonl` terisi.
3. Setelah ukuran ~512KB tercapai → pindah ke `SecEvents.1.jsonl`.
4. `#DUMP STATE|H=<hmac>` menampilkan `"logPersist":"1"`.
5. Nonaktifkan: `#SET LOGPERSIST=0|H=<hmac>` → berhenti menulis, file tetap utuh.

### Keterbatasan / Langkah Lanjut

- Tidak ada flush buffer eksplisit (mengandalkan CloseFile per write, I/O sync tapi overhead lebih tinggi).
- Belum ada timestamp resolusi tinggi (menggunakan `GetTickCount` di payload event seperti sebelumnya).
- Belum ada kompresi / pemusnahan aman.
- Belum ada proteksi anti-tamper / signing log.
- Potensi peningkatan: event `LOG_ROTATE`, hash chaining, CRC footer per file, background batching.


## Module Section Integrity (Phase 1 - 2025-09)

Detektor ini melakukan baseline hash section PE (ntdll.dll, kernel32.dll, user32.dll) dan memverifikasi periodik untuk mendeteksi patching runtime (inline hook massal, overwrites) yang tidak ter-cover penuh oleh prolog/IAT/EAT checker.

Rasional: Memberi sinyal coarse-grained bila ada perubahan besar pada section eksekusi/data yang menunjukan injeksi / loader abnormal.

### Mekanisme

1. Tick pertama: enumerasi hingga `MEM_SEC_MAX_SECTIONS` per modul.
2. Simpan: nama, RVA, ukuran, hash FNV32 sederhana (fase awal; bukan kripto).
3. Setiap `MEM_SEC_INTEGRITY_INTERVAL_MS` ms: re-hash baseline section.
4. Perbedaan → event mismatch dan terminasi (fase 1 agresif, akan ditambah mode audit).

### Konfigurasi

| Konstanta | Deskripsi |
|-----------|----------|
| `MEM_SEC_INTEGRITY_INTERVAL_MS` | Interval pemeriksaan ulang |
| `MEM_SEC_MAX_SECTIONS` | Batas section yang direkam |
| `MEM_SEC_HASH_ALGO` | Placeholder nama algoritma (saat ini FNV32 internal) |

### Event

| Event | Arti |
|-------|-----|
| `ModuleSectionIntegrity BASELINE` | Baseline modul selesai |
| `ModuleSectionIntegrity MISMATCH` | Delta hash / kehilangan section ditemukan |

Contoh (disederhanakan):

```text
[Detection] ModuleSectionIntegrity BASELINE mod=ntdll.dll sections=10
[Detection] ModuleSectionIntegrity MISMATCH mod=kernel32.dll deltas=[diff:.text]
```

### Keterbatasan Fase 1

- Hash mudah di-collide secara teoritis (bukan anti-tamper kuat).
- Tidak ada whitelist offset intra-section.
- Tidak validasi terhadap image disk segar.
- Mismatch langsung exit (false positive risk di beberapa environment hooking legitimate).

### Roadmap Lanjut

- Ganti ke SHA-256 truncated 64-bit.
- Tambah cross-check mapping disk (lihat pola `NtdllIntegrity`).
- Whitelist offset / rentang via policy.
- Mode audit-only dan escalation progresif.



Keterbatasan Saat Ini:

- Per-event type (tidak global agregat).
- Tidak ada prioritas (semua jenis di daftar diperlakukan sama).
- Tidak persist antar sesi.

Future Enhancement Ide:

- Mode adaptive (threshold naik/turun berdasar baseline rata-rata harian).
- Per-session dan global bucket terpisah.
- Integrasi dengan external metrics sink (emit delta suppressed per interval tetap).

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

## Internal Self-Check (Lightweight)

Suite test lama & harness telah dinetralkan dan tidak lagi dibangun. Sebagai gantinya tersedia self-check ringan opsional untuk memverifikasi komponen inti tanpa membuka permukaan kode uji lengkap.

Aktivasi:

Set environment variable sebelum proses host memuat DLL:

```bat
set OBLIVION_SELFTEST=1
```

Saat `DllMain` (PROCESS_ATTACH), fungsi `RunInternalSelfCheck()` akan:

- Mengecilkan ring logger lalu mengisi >N entri untuk memastikan cap bekerja.
- Memverifikasi determinisme `Sha256HexLower` dan derivasi session key.
- Mengirim ping log ke pipe jika pipe client sudah berjalan.
- Merekam hasil ke log Security (`LogSec`).

Output ringkas: baris status `[SC PASS]/[SC FAIL]` di buffer log (dapat diambil via mekanisme snapshot / server log pipe).

Tidak Ada Coverage Untuk:

- Correlation scoring & cooldown.
- Scheduler exception resilience (hanya implicit melalui operasional biasa).
- Integrity hashing modul.

Ekstensi Rekomendasi (Opsional):

| Area | Ide Self-Check Tambahan |
|------|--------------------------|
| Replay Guard | Injeksi dua NONCE sama → pastikan kedua tidak diterima (butuh hook server) |
| HMAC | Bangun payload sintetis + recompute server-side hasil sama |
| Scheduler | Tambah dummy detector tick counter selama 100–200 ms |
| Correlator | Simulasi beberapa kategori event dan baca skor final |

Rollback: hapus `OBLIVION_SELFTEST` atau buang pemanggilan `RunInternalSelfCheck()` di `dllmain.cpp`.

## Lisensi

Hanya untuk proteksi aplikasi Anda sendiri. Tidak untuk distribusi publik tanpa izin penulis.

## Logger Enhanced (2025-09)

Logger ditingkatkan dari sekadar OutputDebugString menjadi sistem multi-fitur:

- Level: Debug, Info, Warn, Error, Security.
- Ring buffer in-memory (default 256 entri) dapat di-snapshot untuk diagnosa atau test.
- File sink opsional (`EnableFileSink(path, append)`) dengan append atau truncate.
- Filter level dinamis (`SetLevel(LogLevel::Warn)` menahan log level lebih rendah).
- API kompatibel lama: `Log(L"msg")` masih bekerja (mapped ke Info).
- API baru: `LogDbg`, `LogWarn`, `LogErr`, `LogSec`.

Contoh penggunaan:

```cpp
using namespace OblivionEye;
LoggerBackend::Instance().SetLevel(LogLevel::Debug);
LoggerBackend::Instance().EnableFileSink(L"oblivioneye.log");
LogDbg(L"detector start");
LogSec(L"suspicious handle detected");
```

Snapshot ring buffer (misal untuk diagnosa):

```cpp
auto entries = LoggerBackend::Instance().Snapshot();
for (auto &e : entries) {/* dump / analyze */}
```

## Continuous Integration (CI)

Workflow GitHub Actions (`.github/workflows/ci.yml`) ditambahkan untuk:

1. Build proyek `Oblivion_Tests` (Debug x64)
2. Menjalankan executable test
3. Memutus workflow (fail) jika exit code != 0

Trigger: push / PR ke branch `main` atau `master`, dan manual dispatch.

YAML ringkas:

```yaml
name: CI
on: [push, pull_request]
jobs:
  build-test-windows:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4
      - uses: microsoft/setup-msbuild@v2
      - run: msbuild OblivionEye.sln /t:Oblivion_Tests /p:Configuration=Debug /p:Platform=x64 /m
      - run: .\\x64\\Debug\\Oblivion_Tests.exe
```

Rencana lanjutan CI:

- Matrix build (x86 + Release)
- Artifact upload (log file, policy baseline)
- Static analysis (clang-tidy / CodeQL)
- Caching build (incremental) untuk percepatan.
