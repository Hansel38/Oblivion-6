#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace OblivionNet {
    // Network ports are deployment configuration, never protocol constants.
    // Accept canonical decimal TCP port values only so malformed environment
    // values cannot be handed to address-resolution APIs.
    inline bool ParseTcpPort(std::string_view text, uint16_t& port) {
        if (text.empty() || text.size() > 5 ||
            (text.size() > 1 && text.front() == '0')) {
            return false;
        }

        uint32_t value = 0;
        for (const unsigned char character : text) {
            if (character < static_cast<unsigned char>('0') ||
                character > static_cast<unsigned char>('9')) {
                return false;
            }
            value = value * 10 +
                static_cast<uint32_t>(character - static_cast<unsigned char>('0'));
            if (value > 65535) {
                return false;
            }
        }

        if (value == 0) {
            return false;
        }

        port = static_cast<uint16_t>(value);
        return true;
    }

    inline std::string FormatTcpPort(uint16_t port) {
        return std::to_string(static_cast<uint32_t>(port));
    }
}
