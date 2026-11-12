#include "pch.h"
#include "file_integrity_check.h"
#include <windows.h>
#include <bcrypt.h> // Header untuk CNG API
#include <fstream>
#include <sstream>
#include <iomanip>
#include <iostream>

// Definisi NTSTATUS jika ntstatus.h tidak tersedia
#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#endif

// Forward declaration
extern void ReportViolationAndExit(const std::wstring& message, const std::string& type, const std::string& details);

#pragma comment(lib, "bcrypt.lib") // Linker library untuk CNG

// DAFTAR FILE DAN HASH YANG DIHARAPKAN
// ANDA HARUS MEMPERBAIKI BAGIAN INI!
// Gunakan tool untuk menghasilkan hash SHA-256 dari file-file ANDA yang bersih.
const std::vector<Oblivion::FileIntegrityChecker::FileHashPair> Oblivion::FileIntegrityChecker::m_filesToCheck = {
    // Contoh: { L"rro.exe", "HASH_SHA_256_DARI_RRO.EXE_ANDA" },
    // Contoh: { L"data.grf", "HASH_SHA_256_DARI_DATA.GRF_ANDA" },
    // Contoh: { L"ragexe.exe", "HASH_SHA_256_DARI_RAGEXE.EXE_ANDA" },
    // TAMBAHKAN FILE LAIN YANG PENTING DI SINI
    { L"RRO.exe", "d5d0dbed64767dd3cf65c4d0bb930c1fa5bb17f3b54770c451a1d9f26528e2e0" }, // Hash SHA256 dari RRO.exe
    { L"Republic.grf", "3bd9d7d1cda7235595f0b3ba9ec178b3d3738c358ff45ac5824805ba4b232581" },  // CONTOH HASH
    { L"DATA.ini", "7b5cea254e67b3cfbc58f710658bdadbb07109146c92f837f467d3c9b8bf5af5" }
};

namespace Oblivion {
    void FileIntegrityChecker::PerformCheck() {
        // Dapatkan direktori tempat client berada
        wchar_t exePath[MAX_PATH];
        GetModuleFileNameW(NULL, exePath, MAX_PATH);
        std::wstring exeDir = exePath;
        size_t lastSlash = exeDir.find_last_of(L"\\/");
        if (lastSlash != std::wstring::npos) {
            exeDir = exeDir.substr(0, lastSlash + 1);
        }

        for (const auto& filePair : m_filesToCheck) {
            std::wstring fullFilePath = exeDir + filePair.relativePath;
            std::string calculatedHash = CalculateSHA256(fullFilePath);

            if (calculatedHash.empty()) {
                // Gagal membaca file (mungkin tidak ada)
                // Konversi file path ke UTF-8 untuk details
                std::string details_utf8;
                int size_needed = WideCharToMultiByte(CP_UTF8, 0, &filePair.relativePath[0], (int)filePair.relativePath.size(), NULL, 0, NULL, NULL);
                if (size_needed > 0) {
                    details_utf8.assign(size_needed, 0);
                    WideCharToMultiByte(CP_UTF8, 0, &filePair.relativePath[0], (int)filePair.relativePath.size(), &details_utf8[0], size_needed, NULL, NULL);
                }
                details_utf8 += " - File not found or corrupted";
                
                ReportViolationAndExit(L"", "FILE_INTEGRITY_FAILED", details_utf8);
            }

            // Bandingkan hash (case-insensitive)
            if (_stricmp(calculatedHash.c_str(), filePair.expectedHash.c_str()) != 0) {
                // Hash tidak cocok, file telah dimodifikasi
                // Konversi file path ke UTF-8 untuk details
                std::string details_utf8;
                int size_needed = WideCharToMultiByte(CP_UTF8, 0, &filePair.relativePath[0], (int)filePair.relativePath.size(), NULL, 0, NULL, NULL);
                if (size_needed > 0) {
                    details_utf8.assign(size_needed, 0);
                    WideCharToMultiByte(CP_UTF8, 0, &filePair.relativePath[0], (int)filePair.relativePath.size(), &details_utf8[0], size_needed, NULL, NULL);
                }
                details_utf8 += " - Hash mismatch. Expected: " + filePair.expectedHash + ", Got: " + calculatedHash;
                
                ReportViolationAndExit(L"", "FILE_MODIFIED", details_utf8);
            }
        }
        // Jika semua lolos, tidak ada yang perlu dilakukan
    }

    std::string FileIntegrityChecker::CalculateSHA256(const std::wstring& filePath) {
        // Gunakan CreateFile dengan share mode untuk membaca file yang sedang dieksekusi
        // Ini penting karena std::ifstream tidak bisa membaca file yang sedang dieksekusi dengan benar
        HANDLE hFile = CreateFileW(
            filePath.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, // Penting: allow sharing untuk file yang sedang dieksekusi
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, // Optimize untuk sequential read
            NULL
        );
        
        if (hFile == INVALID_HANDLE_VALUE) {
            return ""; // File tidak bisa dibuka
        }

        BCRYPT_ALG_HANDLE hAlg = NULL;
        BCRYPT_HASH_HANDLE hHash = NULL;
        NTSTATUS status = STATUS_UNSUCCESSFUL;
        DWORD cbData = 0, cbHash = 0, cbHashObject = 0;
        PBYTE pbHashObject = NULL;
        PBYTE pbHash = NULL;
        std::string result = "";
        const DWORD BUFFER_SIZE = 4096;

        // Buka algoritma SHA-256
        status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
        if (!BCRYPT_SUCCESS(status)) { 
            CloseHandle(hFile);
            return ""; 
        }

        // Hitung ukuran buffer yang diperlukan
        status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(DWORD), &cbData, 0);
        if (!BCRYPT_SUCCESS(status)) { 
            BCryptCloseAlgorithmProvider(hAlg, 0);
            CloseHandle(hFile);
            return ""; 
        }

        status = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&cbHash, sizeof(DWORD), &cbData, 0);
        if (!BCRYPT_SUCCESS(status)) { 
            BCryptCloseAlgorithmProvider(hAlg, 0);
            CloseHandle(hFile);
            return ""; 
        }

        // Alokasikan buffer
        pbHashObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHashObject);
        pbHash = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHash);
        if (!pbHashObject || !pbHash) { 
            if (pbHashObject) HeapFree(GetProcessHeap(), 0, pbHashObject);
            if (pbHash) HeapFree(GetProcessHeap(), 0, pbHash);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            CloseHandle(hFile);
            return ""; 
        }

        // Buat handle hash
        status = BCryptCreateHash(hAlg, &hHash, pbHashObject, cbHashObject, NULL, 0, 0);
        if (!BCRYPT_SUCCESS(status)) { 
            HeapFree(GetProcessHeap(), 0, pbHashObject);
            HeapFree(GetProcessHeap(), 0, pbHash);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            CloseHandle(hFile);
            return ""; 
        }

        // Baca file dan hashkan kontennya menggunakan ReadFile
        BYTE buffer[BUFFER_SIZE];
        DWORD bytesRead = 0;
        while (ReadFile(hFile, buffer, BUFFER_SIZE, &bytesRead, NULL) && bytesRead > 0) {
            status = BCryptHashData(hHash, buffer, bytesRead, 0);
            if (!BCRYPT_SUCCESS(status)) { 
                BCryptDestroyHash(hHash);
                HeapFree(GetProcessHeap(), 0, pbHashObject);
                HeapFree(GetProcessHeap(), 0, pbHash);
                BCryptCloseAlgorithmProvider(hAlg, 0);
                CloseHandle(hFile);
                return ""; 
            }
        }
        
        // Periksa error dari ReadFile (bukan EOF)
        DWORD lastError = GetLastError();
        if (lastError != ERROR_SUCCESS && lastError != ERROR_HANDLE_EOF) {
            BCryptDestroyHash(hHash);
            HeapFree(GetProcessHeap(), 0, pbHashObject);
            HeapFree(GetProcessHeap(), 0, pbHash);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            CloseHandle(hFile);
            return "";
        }

        // Selesaikan perhitungan hash
        status = BCryptFinishHash(hHash, pbHash, cbHash, 0);
        if (!BCRYPT_SUCCESS(status)) { 
            BCryptDestroyHash(hHash);
            HeapFree(GetProcessHeap(), 0, pbHashObject);
            HeapFree(GetProcessHeap(), 0, pbHash);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            CloseHandle(hFile);
            return ""; 
        }

        // Konversi hash byte ke string hex
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (DWORD i = 0; i < cbHash; i++) {
            ss << std::setw(2) << static_cast<unsigned int>(pbHash[i]);
        }
        result = ss.str();

        // Cleanup
        BCryptDestroyHash(hHash);
        HeapFree(GetProcessHeap(), 0, pbHashObject);
        HeapFree(GetProcessHeap(), 0, pbHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        CloseHandle(hFile);

        return result;
    }
}