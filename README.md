![Build Status](https://img.shields.io/badge/build-passing-brightgreen?style=flat-square)
![Platform](https://img.shields.io/badge/platform-Windows-blue?style=flat-square)
![C++](https://img.shields.io/badge/C++-20-blue?style=flat-square)
![License](https://img.shields.io/badge/license-Private-red?style=flat-square)

Oblivion Eye adalah **sistem Anti-Cheat** tingkat lanjut untuk game MMORPG.  
Dibuat dengan **C++20** di **Visual Studio 2022**, terdiri dari **client-side DLL** dan **server-side console app** yang terhubung lewat **TCP Socket (WinSock)** untuk mendeteksi, memblokir, dan melaporkan cheat secara real-time.

---

Oblivion/
├── OblivionEye_Client/
│   ├── include/
│   │   ├── AntiDebugChecker.h
│   │   ├── FileIntegrityChecker.h
│   │   ├── InjectionScanner.h
│   │   ├── MemorySignatureScanner.h
│   │   ├── OverlayScanner.h
│   │   ├── ProcessThreadWatcher.h
│   │   └── SocketClient.h
│   ├── src/
│   │   ├── AntiDebugChecker.cpp
│   │   ├── FileIntegrityChecker.cpp
│   │   ├── InjectionScanner.cpp
│   │   ├── MemorySignatureScanner.cpp
│   │   ├── OverlayScanner.cpp
│   │   ├── ProcessThreadWatcher.cpp
│   │   └── SocketClient.cpp
│   └── main.cpp
│
└── OblivionEye_Server/
    ├── include/
    │   ├── Server.h
    │   └── Validator.h
    ├── src/
    │   ├── Server.cpp
    │   └── Validator.cpp
    └── main.cpp
