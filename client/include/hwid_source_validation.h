#pragma once

#include <algorithm>
#include <string>
#include <string_view>

namespace Oblivion {
    // WMI providers and firmware sometimes return generic placeholders instead
    // of per-device values. These must not count as unique motherboard UUIDs
    // or disk serials when deciding whether an HWID is usable.
    //
    // Deliberately do not rewrite the original WMI value: when at least one
    // source is valid, Generate() keeps the historical input byte-for-byte.
    inline bool IsDeviceSpecificWmiValueAvailable(std::string_view value) {
        std::string compact;
        compact.reserve(value.size());

        for (const unsigned char character : value) {
            if (character <= 0x20 || character == 0x7F ||
                character == '-' || character == '_' ||
                character == '{' || character == '}' || character == '.') {
                continue;
            }

            if (character >= 'a' && character <= 'z') {
                compact.push_back(static_cast<char>(character - ('a' - 'A')));
            } else {
                compact.push_back(static_cast<char>(character));
            }
        }

        if (compact.empty()) return false;

        constexpr std::string_view kTextPlaceholders[] = {
            "UNKNOWN", "NONE", "NULL", "NA", "NOTAPPLICABLE",
            "NOTAVAILABLE", "NOTSPECIFIED", "NOTSET", "NODATA",
            "NOSERIAL", "NOSERIALNUMBER", "SERIALNUMBER", "DEFAULT",
            "DEFAULTSTRING", "SYSTEMSERIALNUMBER", "TOBEFILLED",
            "TOBEFILLEDBYOEM"
        };

        for (const std::string_view placeholder : kTextPlaceholders) {
            if (compact == placeholder) return false;
        }

        // Canonical all-zero/all-F UUIDs and long all-zero/all-F serials are
        // common firmware placeholders. Mixed values remain valid.
        if (compact.size() >= 8) {
            const bool allZeros = std::all_of(
                compact.begin(), compact.end(),
                [](char character) { return character == '0'; });
            const bool allFs = std::all_of(
                compact.begin(), compact.end(),
                [](char character) { return character == 'F'; });
            if (allZeros || allFs) return false;
        }

        return true;
    }
}
