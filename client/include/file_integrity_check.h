#pragma once

#include <string>
#include <vector>

namespace Oblivion {
    class FileIntegrityChecker {
    public:
        // Fungsi utama untuk menjalankan semua pemeriksaan file
        void PerformCheck();

    private:
        // Struktur untuk menyimpan pasangan nama file dan hash yang diharapkan
        struct FileHashPair {
            std::wstring relativePath; // Path relatif dari folder client
            std::string expectedHash;   // Hash SHA-256 dalam format hex
        };

        // Fungsi untuk menghitung hash SHA-256 dari sebuah file
        std::string CalculateSHA256(const std::wstring& filePath);

        // Daftar file yang harus diperiksa integritasnya
        static const std::vector<FileHashPair> m_filesToCheck;
    };
}