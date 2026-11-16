#include "server_secret.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>

namespace {
    struct EnvironmentValue {
        bool isSet = false;
        std::string value;
    };

    EnvironmentValue ReadEnvironmentValue(const char* name) {
        EnvironmentValue output;
#ifdef _WIN32
        char* value = nullptr;
        size_t valueLength = 0;
        const errno_t result = _dupenv_s(&value, &valueLength, name);
        if (result == 0 && value != nullptr) {
            output.isSet = true;
            const size_t contentLength =
                valueLength > 0 ? valueLength - 1 : std::char_traits<char>::length(value);
            output.value.assign(value, contentLength);
        }
        std::free(value);
#else
        const char* value = std::getenv(name);
        if (value != nullptr) {
            output.isSet = true;
            output.value.assign(value);
        }
#endif
        return output;
    }

    bool ContainsPlaceholderMarker(const std::string& value) {
        std::string normalized;
        normalized.reserve(value.size());
        for (const unsigned char character : value) {
            normalized.push_back(static_cast<char>(std::tolower(character)));
        }

        constexpr const char* markers[] = {
            "placeholder",
            "change-me",
            "changeme",
            "your-secret",
            "example-secret",
            "development-secret",
            "replace-this"
        };

        for (const char* marker : markers) {
            if (normalized.find(marker) != std::string::npos) return true;
        }
        return false;
    }

    bool IsUsableSecretText(const std::string& value) {
        if (value.size() < 32 || value.size() > 4096 ||
            ContainsPlaceholderMarker(value)) {
            return false;
        }

        for (const unsigned char character : value) {
            if (character < 0x21 || character > 0x7E) return false;
        }
        return true;
    }

    std::string ReadSecretFile(const std::string& configuredPath) {
        const std::filesystem::path path(configuredPath);
        if (!path.is_absolute()) return {};

        std::ifstream file(path, std::ios::binary);
        if (!file.is_open()) return {};

        file.seekg(0, std::ios::end);
        const std::streamoff length = file.tellg();
        if (length <= 0 || length > 4096) return {};
        file.seekg(0, std::ios::beg);
        if (!file.good()) return {};

        std::string value(static_cast<size_t>(length), '\0');
        file.read(value.data(), static_cast<std::streamsize>(value.size()));
        if (!file || file.gcount() != static_cast<std::streamsize>(value.size())) {
            return {};
        }

        // A single line ending is permitted for operator-managed secret files.
        if (value.size() >= 2 &&
            value[value.size() - 2] == '\r' && value.back() == '\n') {
            value.resize(value.size() - 2);
        } else if (!value.empty() &&
                   (value.back() == '\r' || value.back() == '\n')) {
            value.pop_back();
        }

        return IsUsableSecretText(value) ? value : std::string();
    }
}

namespace OblivionServer {
    std::string GetServerSecret() {
        const EnvironmentValue environmentSecret =
            ReadEnvironmentValue("OBLIVION_SECRET");
        const EnvironmentValue configuredSecretFile =
            ReadEnvironmentValue("OBLIVION_SECRET_FILE");

        // Require exactly one provisioning source. Do not silently prefer one
        // when both are set, and do not fall back to a compiled-in filename.
        if (environmentSecret.isSet == configuredSecretFile.isSet) return {};

        if (environmentSecret.isSet) {
            return IsUsableSecretText(environmentSecret.value)
                ? environmentSecret.value : std::string();
        }

        return ReadSecretFile(configuredSecretFile.value);
    }
}
