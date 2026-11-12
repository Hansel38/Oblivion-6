#pragma once

#include <vector>
#include <string>

// Menggunakan wstring untuk kompatibilitas dengan Windows API yang seringkali menggunakan wide char
namespace Oblivion {
    // Fungsi untuk memeriksa apakah nama proses ada di dalam daftar hitam
    bool IsProcessBlacklisted(const std::wstring& processName);
}