#include <string>
#include <vector>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <limits.h>
#if !defined(_WIN32)
#include <unistd.h>
#endif
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
            // _dupenv_s reports the buffer size including the terminating NUL.
            // Construct from the C string so the terminator is not part of the key.
            cached = std::string(envSecret);
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
        // Resolve the executable directory with a bounded dynamic buffer.
        // Never fall back to the process working directory for a secret file.
        std::wstring executableDirectory;
        std::vector<wchar_t> pathBuffer(MAX_PATH);
        constexpr size_t kMaximumPathCapacity = 32768;
        while (pathBuffer.size() <= kMaximumPathCapacity) {
            const DWORD pathLength = GetModuleFileNameW(
                nullptr, pathBuffer.data(), static_cast<DWORD>(pathBuffer.size()));
            if (pathLength == 0) {
                break;
            }

            if (pathLength < pathBuffer.size()) {
                const std::wstring executablePath(pathBuffer.data(), pathLength);
                const size_t lastSlash = executablePath.find_last_of(L"\\/");
                if (lastSlash != std::wstring::npos) {
                    executableDirectory = executablePath.substr(0, lastSlash + 1);
                }
                break;
            }

            if (pathBuffer.size() == kMaximumPathCapacity) {
                break;
            }
            const size_t nextCapacity =
                pathBuffer.size() > kMaximumPathCapacity / 2
                    ? kMaximumPathCapacity : pathBuffer.size() * 2;
            pathBuffer.resize(nextCapacity);
        }

        if (!executableDirectory.empty()) {
            const std::wstring secretPathW = executableDirectory + L"secret.dat";
            HANDLE hFile = CreateFileW(secretPathW.c_str(), GENERIC_READ,
                FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hFile != INVALID_HANDLE_VALUE) {
                const DWORD fileSize = GetFileSize(hFile, NULL);
                if (fileSize > 0 && fileSize < 1024) {
                    std::vector<unsigned char> encoded(fileSize);
                    DWORD readBytes = 0;
                    if (ReadFile(hFile, encoded.data(), fileSize, &readBytes, NULL) &&
                        readBytes == fileSize) {
                        secret.reserve(fileSize);
                        for (size_t i = 0; i < encoded.size(); ++i) {
                            const unsigned char key =
                                static_cast<unsigned char>(0x5A + ((i * 7) % 0x3F));
                            secret += static_cast<char>(encoded[i] ^ key);
                        }
                        CloseHandle(hFile);
                        cached = secret;
                        return cached;
                    }
                }
                CloseHandle(hFile);
            }
        }
#else
        // Linux: resolve secret.dat relative to the executable, not the process CWD.
        char executablePath[PATH_MAX + 1] = {};
        const ssize_t executablePathLength =
            readlink("/proc/self/exe", executablePath, PATH_MAX);
        std::string secretFilePath;
        if (executablePathLength > 0 && executablePathLength < PATH_MAX) {
            executablePath[executablePathLength] = '\0';
            std::string executablePathString(executablePath,
                                               static_cast<size_t>(executablePathLength));
            const size_t separator = executablePathString.find_last_of('/');
            secretFilePath = separator == std::string::npos
                ? std::string("secret.dat")
                : executablePathString.substr(0, separator + 1) + "secret.dat";
        }

        if (!secretFilePath.empty()) {
            FILE* f = fopen(secretFilePath.c_str(), "rb");
            if (f) {
                if (fseek(f, 0, SEEK_END) == 0) {
                    const long fileSize = ftell(f);
                    if (fileSize > 0 && fileSize < 1024 && fseek(f, 0, SEEK_SET) == 0) {
                        std::vector<unsigned char> encoded(static_cast<size_t>(fileSize));
                        const size_t bytesRead = fread(encoded.data(), 1, encoded.size(), f);
                        const int trailingByte = fgetc(f);
                        const bool completeRead = bytesRead == encoded.size() &&
                                                  trailingByte == EOF && !ferror(f);
                        if (completeRead) {
                            secret.reserve(encoded.size());
                            for (size_t i = 0; i < encoded.size(); ++i) {
                                const unsigned char key =
                                    static_cast<unsigned char>(0x5A + ((i * 7) % 0x3F));
                                secret += static_cast<char>(encoded[i] ^ key);
                            }
                        }
                    }
                }
                fclose(f);
            }
        }

        if (!secret.empty()) {
            cached = secret;
            return cached;
        }
#endif

        // Release builds must fail closed when no production secret is configured.
#if defined(_DEBUG)
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
#else
        return {};
#endif
    }
}
