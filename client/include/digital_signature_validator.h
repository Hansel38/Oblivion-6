#pragma once

#include <windows.h>
#include <vector>
#include <string>
#include <map>

namespace Oblivion {
    class DigitalSignatureValidator {
    public:
        DigitalSignatureValidator();
        ~DigitalSignatureValidator();

        // Fungsi utama untuk memindai semua modul
        void PerformScan();

        // Fungsi untuk verifikasi process executable (untuk whitelist verification)
        // Mengembalikan true jika signature valid dan publisher sesuai ekspektasi
        static bool VerifyProcessSignature(const std::wstring& processPath, const std::wstring& expectedPublisher);
        
        // Fungsi untuk mendapatkan publisher dari file executable
        static bool GetFilePublisher(const std::wstring& filePath, std::wstring& publisherName);

        // Public access ke expected publishers map untuk cross-verification
        static const std::map<std::wstring, std::wstring> m_expectedPublishers;

    private:
        // Fungsi untuk memeriksa apakah sebuah modul tepercaya
        bool IsModuleTrusted(HMODULE hModule, std::wstring& moduleName);

        // Fungsi untuk mendapatkan nama penerbit dari sertifikat
        bool GetCertificateSubjectName(HMODULE hModule, std::wstring& subjectName);

        // Fungsi helper untuk verifikasi signature file
        static bool VerifyFileSignature(const std::wstring& filePath);

        // Daftar penerbit yang dipercaya
        static const std::vector<std::wstring> m_trustedPublishers;
        
        // Daftar DLL yang diizinkan meskipun tidak ditandatangani (DLL legitimate dari game/engine)
        static const std::vector<std::wstring> m_allowedUnsignedDlls;
    };
}