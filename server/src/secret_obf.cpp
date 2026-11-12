#include <string>
#include <vector>
#include <cstdint>
#include <cstring>
#include "secret_obf.h"
#if defined(_WIN32)
#include <windows.h>
#endif

// Obfuscation ringan untuk shared secret. Hindari menyimpan literal string.
// PENTING: Algoritma HARUS SAMA dengan client side!

namespace OblivionServer {
    std::string GetServerSecret() {
        static std::string cached;
        if (!cached.empty()) return cached;

        // 1) Environment variable override
        // Aman: gunakan _dupenv_s di Windows
    #if defined(_WIN32)
        char* envSecret = nullptr; size_t envLen = 0;
        if (_dupenv_s(&envSecret, &envLen, "OBLIVION_SECRET") == 0 && envSecret && envLen > 0) {
            cached = std::string(envSecret, envLen);
            free(envSecret);
            return cached;
        }
    #else
        const char* envSecret = getenv("OBLIVION_SECRET");
        if (envSecret && *envSecret) {
            cached = std::string(envSecret);
            return cached;
        }
    #endif

        // 2) File-based secret (secret.dat) encoded dengan XOR agar tidak muncul literal
        //    Lokasi: berdampingan dengan server executable
        std::string secret;
#if defined(_WIN32)
        wchar_t pathBuf[MAX_PATH] = {0};
        DWORD sz = GetModuleFileNameW(NULL, pathBuf, MAX_PATH);
        std::wstring exeDir;
        if (sz > 0) {
            exeDir.assign(pathBuf, sz);
            size_t lastSlash = exeDir.find_last_of(L"\\/");
            if (lastSlash != std::wstring::npos) exeDir = exeDir.substr(0, lastSlash + 1);
        }
        std::wstring secretPathW = exeDir + L"secret.dat";
        HANDLE hFile = CreateFileW(secretPathW.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            DWORD fileSize = GetFileSize(hFile, NULL);
            if (fileSize > 0 && fileSize < 1024) {
                std::vector<unsigned char> encoded(fileSize);
                DWORD readBytes = 0;
                if (ReadFile(hFile, encoded.data(), fileSize, &readBytes, NULL) && readBytes == fileSize) {
                    secret.reserve(fileSize);
                    for (size_t i = 0; i < encoded.size(); ++i) {
                        unsigned char key = (unsigned char)(0x5A + ((i * 7) % 0x3F));
                        secret += (char)(encoded[i] ^ key);
                    }
                    CloseHandle(hFile);
                    cached = secret;
                    return cached;
                }
            }
            CloseHandle(hFile);
        }
#else
        // Non-Windows: simple file read from current dir
        FILE* f = fopen("secret.dat", "rb");
        if (f) {
            std::vector<unsigned char> encoded;
            unsigned char buf[256];
            size_t r;
            while ((r = fread(buf, 1, sizeof(buf), f)) > 0) {
                encoded.insert(encoded.end(), buf, buf + r);
            }
            fclose(f);
            for (size_t i = 0; i < encoded.size(); ++i) {
                unsigned char key = (unsigned char)(0x5A + ((i * 7) % 0x3F));
                secret += (char)(encoded[i] ^ key);
            }
            if (!secret.empty()) {
                cached = secret;
                return cached;
            }
        }
#endif

        // 3) Fallback development value jika tidak ada konfigurasi
        const char* devDefault = "DEV_SECRET_NOT_SET";
        size_t len = strlen(devDefault);
        std::vector<unsigned char> encoded(len);
        for (size_t i = 0; i < len; ++i) {
            unsigned char key = (unsigned char)(0x5A + ((i * 7) % 0x3F));
            encoded[i] = (unsigned char)(devDefault[i] ^ key);
        }
        secret.reserve(len);
        for (size_t i = 0; i < len; ++i) {
            unsigned char key = (unsigned char)(0x5A + ((i * 7) % 0x3F));
            secret += (char)(encoded[i] ^ key);
        }

        cached = secret;
        return cached;
    }
}
