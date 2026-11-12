#pragma once
#include <string>

// Obfuscation ringan untuk menyulitkan pencarian literal secret melalui static analysis.
// Catatan: Ini TIDAK memberikan keamanan kriptografi, hanya mengurangi visibilitas langsung.
// Strategi: Array diencode XOR + permutasi sederhana; decode satu kali saat pertama dipanggil.
namespace Oblivion {
    std::string GetClientSecret();
}
