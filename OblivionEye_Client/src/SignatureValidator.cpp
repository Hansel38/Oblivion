#include "../include/SignatureValidator.h"
#include <windows.h>
#include <wintrust.h>
#include <softpub.h>
#include <iostream>
#include <thread>
#include <chrono>
#include <vector>
#include "../include/Logger.h"

#pragma comment(lib, "wintrust.lib")

// Fungsi untuk memvalidasi signature file
bool ValidateFileSignature(const std::string& filePath) {
    WINTRUST_FILE_INFO FileData;
    GUID WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA WinTrustData;
    DWORD dwVerifySignResult = 0;

    // Inisialisasi struktur WINTRUST_FILE_INFO
    memset(&FileData, 0, sizeof(FileData));
    FileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
    FileData.pcwszFilePath = NULL;
    FileData.hFile = NULL;
    FileData.pgKnownSubject = NULL;

    // Inisialisasi struktur WINTRUST_DATA
    memset(&WinTrustData, 0, sizeof(WinTrustData));
    WinTrustData.cbStruct = sizeof(WinTrustData);
    WinTrustData.pPolicyCallbackData = NULL;
    WinTrustData.pSIPClientData = NULL;
    WinTrustData.dwUIChoice = WTD_UI_NONE;
    WinTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    WinTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    WinTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
    WinTrustData.hWVTStateData = NULL;
    WinTrustData.pwszURLReference = NULL;
    WinTrustData.dwProvFlags = WTD_SAFER_FLAG;
    WinTrustData.dwUIContext = 0;
    WinTrustData.pFile = &FileData;

    // Konversi string ke wide string
    int wideStringLength = MultiByteToWideChar(CP_UTF8, 0, filePath.c_str(), -1, NULL, 0);
    if (wideStringLength == 0) {
        Logger::Log(LOG_ERROR, "Failed to convert file path to wide string: " + filePath);
        return true; // Anggap aman jika gagal konversi
    }

    LPWSTR wideString = new WCHAR[wideStringLength];
    MultiByteToWideChar(CP_UTF8, 0, filePath.c_str(), -1, wideString, wideStringLength);

    FileData.pcwszFilePath = wideString;

    // Verifikasi signature
    dwVerifySignResult = WinVerifyTrust(NULL, &WVTPolicyGUID, &WinTrustData);

    // Bersihkan state data
    WinTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &WVTPolicyGUID, &WinTrustData);

    delete[] wideString;

    // Cek hasil verifikasi
    if (dwVerifySignResult == ERROR_SUCCESS) {
        Logger::Log(LOG_INFO, "Valid signature found for: " + filePath);
        return true; // Signature valid
    }
    else {
        // HANYA anggap sebagai ancaman jika signature INVALID, bukan jika tidak ada
        switch (dwVerifySignResult) {
        case TRUST_E_NOSIGNATURE:
            // Tidak ada signature - tidak selalu berbahaya
            Logger::Log(LOG_INFO, "No signature found for: " + filePath + " (Not necessarily malicious)");
            return true; // Anggap aman untuk file tanpa signature
        case TRUST_E_BAD_DIGEST:
            Logger::Log(LOG_DETECTED, "Invalid signature (bad digest) for: " + filePath);
            return false;
        case CERT_E_UNTRUSTEDROOT:
            Logger::Log(LOG_DETECTED, "Untrusted root certificate for: " + filePath);
            return false;
        case TRUST_E_EXPLICIT_DISTRUST:
            Logger::Log(LOG_DETECTED, "Explicitly distrusted certificate for: " + filePath);
            return false;
        default:
            Logger::Log(LOG_INFO, "Signature verification result for: " + filePath +
                " (Result: " + std::to_string(dwVerifySignResult) + ")");
            // Untuk hasil lain, anggap aman kecuali benar-benar invalid
            return true;
        }
    }
}

// Fungsi untuk mendapatkan path executable saat ini
std::string GetCurrentExecutablePath() {
    char buffer[MAX_PATH];
    GetModuleFileNameA(NULL, buffer, MAX_PATH);
    return std::string(buffer);
}

// Fungsi untuk validasi signature executable
bool ValidateExecutableSignature() {
    std::string exePath = GetCurrentExecutablePath();
    Logger::Log(LOG_INFO, "Validating signature for executable: " + exePath);

    return ValidateFileSignature(exePath);
}

// Fungsi untuk validasi signature DLL kita sendiri
bool ValidateOwnDLLSignature() {
    char dllPath[MAX_PATH];
    HMODULE hModule = GetModuleHandleA("OblivionEye_Client.dll");
    if (hModule) {
        GetModuleFileNameA(hModule, dllPath, MAX_PATH);
        std::string dllPathStr(dllPath);
        Logger::Log(LOG_INFO, "Validating signature for own DLL: " + dllPathStr);
        return ValidateFileSignature(dllPathStr);
    }
    return true; // Anggap aman jika tidak bisa mendapatkan path
}

// Fungsi untuk validasi signature file penting sistem
bool ValidateSystemFilesSignature() {
    // Validasi beberapa file sistem penting
    std::vector<std::string> systemFiles = {
        "C:\\Windows\\System32\\kernel32.dll",
        "C:\\Windows\\System32\\ntdll.dll",
        "C:\\Windows\\System32\\user32.dll"
    };

    bool allValid = true;
    for (const auto& file : systemFiles) {
        if (!ValidateFileSignature(file)) {
            // Hanya log jika signature system file invalid
            if (GetLastError() != 0) { // Jika benar-benar error
                allValid = false;
            }
        }
    }
    return allValid;
}

// Fungsi utama untuk validasi signature
bool PerformSignatureValidation() {
    bool exeValid = ValidateExecutableSignature();
    bool dllValid = ValidateOwnDLLSignature();
    bool systemValid = ValidateSystemFilesSignature();

    return exeValid && dllValid && systemValid;
}

// Fungsi untuk scanning continuous
void ContinuousSignatureValidation() {
    Logger::Log(LOG_INFO, "Signature Validator started");

    // Validasi pertama kali saat startup
    if (!PerformSignatureValidation()) {
        Logger::Log(LOG_DETECTED, "Invalid signature detected on startup, closing client");
        ExitProcess(0);
    }

    // Validasi berkala setiap 60 detik (opsional, bisa dikurangi frekuensinya)
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(60));
        // Untuk signature validation, cukup saat startup saja
        /*
        if (!PerformSignatureValidation()) {
            Logger::Log(LOG_DETECTED, "Invalid signature detected during runtime, closing client");
            ExitProcess(0);
        }
        */
    }
}