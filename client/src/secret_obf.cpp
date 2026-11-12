#include "pch.h"
#include "secret_obf.h"
#include <vector>
#include <windows.h>

// Obfuscation ringan untuk shared secret. Hindari menyimpan literal string.

namespace Oblivion {
    std::string GetClientSecret() {
        static std::string cached;
        if (!cached.empty()) {
            return cached;
        }

        // 1) Coba ambil dari environment variable (runtime configurable)
        //    Set dengan nama OBLIVION_SECRET untuk override tanpa recompile
        wchar_t envBuf[256] = {0};
        DWORD envLen = GetEnvironmentVariableW(L"OBLIVION_SECRET", envBuf, 255);
        if (envLen > 0 && envLen < 255) {
            int size_needed = WideCharToMultiByte(CP_UTF8, 0, envBuf, (int)envLen, NULL, 0, NULL, NULL);
            if (size_needed > 0) {
                std::string envSecret(size_needed, '\0');
                WideCharToMultiByte(CP_UTF8, 0, envBuf, (int)envLen, &envSecret[0], size_needed, NULL, NULL);
                cached = envSecret;
                return cached;
            }
        }

        // 2) Coba load dari file berdampingan (secret.dat) untuk produksi
        //    File berisi bytes yang sudah di-XOR (encoded) agar tidak terlihat literal
        std::wstring exePathW;
        wchar_t pathBuf[MAX_PATH] = {0};
        DWORD sz = GetModuleFileNameW(NULL, pathBuf, MAX_PATH);
        if (sz > 0) {
            exePathW.assign(pathBuf, sz);
            size_t lastSlash = exePathW.find_last_of(L"\\/");
            if (lastSlash != std::wstring::npos) exePathW = exePathW.substr(0, lastSlash + 1);
        }
        std::wstring secretPathW = exePathW + L"secret.dat";
        HANDLE hFile = CreateFileW(secretPathW.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            DWORD fileSize = GetFileSize(hFile, NULL);
            if (fileSize > 0 && fileSize < 1024) {
                std::vector<unsigned char> encoded(fileSize);
                DWORD readBytes = 0;
                if (ReadFile(hFile, encoded.data(), fileSize, &readBytes, NULL) && readBytes == fileSize) {
                    std::string secret;
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

        // 3) Fallback development: gunakan nilai dummy agar terlihat jelas di log
        //    Disarankan untuk produksi set via ENV atau file secret.dat
        const char* devDefault = "DEV_SECRET_NOT_SET";
        size_t len = strlen(devDefault);
        std::vector<unsigned char> encoded(len);
        for (size_t i = 0; i < len; ++i) {
            unsigned char key = (unsigned char)(0x5A + ((i * 7) % 0x3F));
            encoded[i] = (unsigned char)(devDefault[i] ^ key);
        }
        std::string secret;
        secret.reserve(len);
        for (size_t i = 0; i < len; ++i) {
            unsigned char key = (unsigned char)(0x5A + ((i * 7) % 0x3F));
            secret += (char)(encoded[i] ^ key);
        }

        cached = secret;
        return cached;
    }
}
