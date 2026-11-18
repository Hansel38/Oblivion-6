#include "../common/secret_validation.h"

#include <cstdlib>
#include <iostream>
#include <string>

namespace {
    void Require(bool condition, const char* message) {
        if (!condition) {
            std::cerr << "FAILED: " << message << std::endl;
            std::abort();
        }
    }
}

int main() {
    const std::string validSecret = "0123456789abcdef0123456789abcdef";
    Require(OblivionSecrets::IsUsableSecretText(validSecret),
            "32 printable ASCII bytes should be accepted");

    Require(!OblivionSecrets::IsUsableSecretText(validSecret.substr(1)),
            "31 bytes should be rejected");

    Require(OblivionSecrets::IsUsableSecretText(std::string(4096, 'A')),
            "4096 printable ASCII bytes should be accepted");
    Require(!OblivionSecrets::IsUsableSecretText(std::string(4097, 'A')),
            "4097 bytes should be rejected");

    Require(!OblivionSecrets::IsUsableSecretText(
                "0123456789abcdef0123456789abcde "),
            "space/control whitespace must be rejected");
    Require(!OblivionSecrets::IsUsableSecretText(
                "0123456789abcdef0123456789abcde\n"),
            "line endings must be rejected in the final secret text");
    Require(!OblivionSecrets::IsUsableSecretText(
                std::string(31, 'A') + static_cast<char>(0x7F)),
            "DEL must be rejected");
    Require(!OblivionSecrets::IsUsableSecretText(
                std::string(31, 'A') + static_cast<char>(0x80)),
            "non-ASCII bytes must be rejected");

    const std::string markers[] = {
        "placeholder", "PLACEHOLDER", "change-me", "CHANGEME",
        "your-secret", "example-secret", "development-secret", "replace-this"
    };
    for (const auto& marker : markers) {
        const std::string candidate = "prefix-0123456789-" + marker +
                                      "-0123456789abcdef";
        Require(!OblivionSecrets::IsUsableSecretText(candidate),
                "placeholder markers must be rejected case-insensitively");
    }

    std::cout << "Shared secret validation tests passed" << std::endl;
    return 0;
}
