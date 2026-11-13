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

        // 1) Read OBLIVION_SECRET with a bounded, dynamically sized buffer.
        constexpr DWORD kMaxSecretCharacters = 4096;
        SetLastError(ERROR_SUCCESS);
        const DWORD envCapacity =
            GetEnvironmentVariableW(L"OBLIVION_SECRET", nullptr, 0);
        if (envCapacity > 0) {
            if (envCapacity > kMaxSecretCharacters + 1) {
                return {};
            }

            std::vector<wchar_t> envBuffer(envCapacity);
            const DWORD envLength = GetEnvironmentVariableW(
                L"OBLIVION_SECRET", envBuffer.data(), envCapacity);
            if (envLength == 0 || envLength >= envCapacity) {
                return {};
            }

            const int inputLength = static_cast<int>(envLength);
            const int sizeNeeded = WideCharToMultiByte(
                CP_UTF8, WC_ERR_INVALID_CHARS, envBuffer.data(), inputLength,
                nullptr, 0, nullptr, nullptr);
            if (sizeNeeded <= 0 || sizeNeeded > static_cast<int>(kMaxSecretCharacters)) {
                return {};
            }

            std::string envSecret(static_cast<size_t>(sizeNeeded), '\0');
            const int converted = WideCharToMultiByte(
                CP_UTF8, WC_ERR_INVALID_CHARS, envBuffer.data(), inputLength,
                &envSecret[0], sizeNeeded, nullptr, nullptr);
            if (converted != sizeNeeded) {
                return {};
            }

            cached = std::move(envSecret);
            return cached;
        }

        const DWORD envError = GetLastError();
        if (envError != ERROR_SUCCESS && envError != ERROR_ENVVAR_NOT_FOUND) {
            return {};
        }

        // 2) Read secret.dat only when the executable directory is resolved.
        // XOR is obfuscation, not cryptographic protection.
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
                        std::string secret;
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

        // Release builds must not fall back to a public, known development secret.
#if defined(_DEBUG)
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
#else
        return {};
#endif
    }
}
