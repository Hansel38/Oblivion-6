#pragma once
#include <string>

// Obfuscation ringan server-side untuk menyembunyikan secret dari string literal.
// Catatan: Hanya anti-string-scanning, bukan proteksi kriptografi.
namespace OblivionServer {
    std::string GetServerSecret();
}
