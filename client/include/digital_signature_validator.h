#pragma once

#include <windows.h>
#include <vector>
#include <string>
#include <map>

namespace Oblivion {
    class DigitalSignatureValidator {
    public:
        enum class ProcessSignatureResult {
            Trusted,
            Untrusted,
            Incomplete
        };

        DigitalSignatureValidator();
        ~DigitalSignatureValidator();

        // Fungsi utama untuk memindai semua modul
        void PerformScan();

        // Fungsi untuk verifikasi process executable (untuk whitelist verification)
        // Mengembalikan true jika signature valid dan publisher sesuai ekspektasi
        static ProcessSignatureResult VerifyProcessSignatureDetailed(
            const std::wstring& processPath,
            const std::wstring& expectedPublisher,
            std::wstring& failureReason);
        static bool VerifyProcessSignature(
            const std::wstring& processPath,
            const std::wstring& expectedPublisher);
        // Windows-core process names are accepted only after path containment
        // in the Windows directory has been established by the caller.
        static ProcessSignatureResult VerifyWindowsSystemProcessSignatureDetailed(
            const std::wstring& processPath,
            std::wstring& failureReason);
        
        // Fungsi untuk mendapatkan publisher dari file executable
        static bool GetFilePublisher(const std::wstring& filePath, std::wstring& publisherName);

        // Public access ke expected publishers map untuk cross-verification
        static const std::map<std::wstring, std::wstring> m_expectedPublishers;

    private:
        // Fungsi untuk memeriksa apakah sebuah modul tepercaya
        enum class ModuleTrustResult {
            Trusted,
            Untrusted,
            Incomplete
        };

        ModuleTrustResult IsModuleTrusted(
            const std::wstring& modulePath,
            const std::wstring& moduleName,
            std::wstring& failureReason);

        // Fungsi untuk mendapatkan nama penerbit dari sertifikat
        bool GetCertificateSubjectName(HMODULE hModule, std::wstring& subjectName);

        // Fungsi helper untuk verifikasi signature file
        static bool VerifyFileSignature(
            const std::wstring& filePath,
            LONG* trustStatus = nullptr);

        // Daftar penerbit yang dipercaya
        static const std::vector<std::wstring> m_trustedPublishers;
        
        // Daftar DLL yang diizinkan meskipun tidak ditandatangani (DLL legitimate dari game/engine)
        static const std::vector<std::wstring> m_allowedUnsignedDlls;
    };
}