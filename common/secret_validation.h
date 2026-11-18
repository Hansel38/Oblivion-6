#pragma once

#include <cstddef>
#include <string_view>

namespace OblivionSecrets {
    inline bool ContainsPlaceholderMarker(std::string_view value) noexcept {
        constexpr std::string_view markers[] = {
            "placeholder",
            "change-me",
            "changeme",
            "your-secret",
            "example-secret",
            "development-secret",
            "replace-this"
        };

        for (const std::string_view marker : markers) {
            if (marker.size() > value.size()) continue;
            for (std::size_t offset = 0; offset <= value.size() - marker.size(); ++offset) {
                bool matched = true;
                for (std::size_t index = 0; index < marker.size(); ++index) {
                    unsigned char character =
                        static_cast<unsigned char>(value[offset + index]);
                    if (character >= 'A' && character <= 'Z') {
                        character = static_cast<unsigned char>(character + ('a' - 'A'));
                    }
                    if (character != static_cast<unsigned char>(marker[index])) {
                        matched = false;
                        break;
                    }
                }
                if (matched) return true;
            }
        }
        return false;
    }

    // The server and client must accept exactly the same provisioning format:
    // 32–4096 printable ASCII bytes, with no placeholder/example markers.
    inline bool IsUsableSecretText(std::string_view value) noexcept {
        if (value.size() < 32 || value.size() > 4096 ||
            ContainsPlaceholderMarker(value)) {
            return false;
        }

        for (const unsigned char character : value) {
            if (character < 0x21 || character > 0x7E) return false;
        }
        return true;
    }
}
