#pragma once

#include <cstdint>
#include <limits>
#include <string>

namespace OblivionNet {
    // Preserve the wire contract: 1-20 ASCII decimal digits fitting uint64_t.
    inline bool IsValidChallengeNonce(const std::string& nonce) {
        if (nonce.empty() || nonce.size() > 20) {
            return false;
        }

        uint64_t value = 0;
        for (const unsigned char digitCharacter : nonce) {
            if (digitCharacter < static_cast<unsigned char>('0') ||
                digitCharacter > static_cast<unsigned char>('9')) {
                return false;
            }

            const uint64_t digit =
                static_cast<uint64_t>(digitCharacter - static_cast<unsigned char>('0'));
            if (value >
                ((std::numeric_limits<uint64_t>::max)() - digit) / 10) {
                return false;
            }

            value = value * 10 + digit;
        }

        return true;
    }
}
