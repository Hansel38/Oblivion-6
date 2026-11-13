#include "protocol_validation.h"

#include <cstdlib>
#include <iostream>
#include <string>
#include <utility>
#include <vector>

namespace {
    void Require(bool condition, const char* description) {
        if (!condition) {
            std::cerr << "FAILED: " << description << std::endl;
            std::abort();
        }
    }
}

int main() {
    const std::vector<std::pair<std::string, bool>> cases = {
        {"", false},
        {"0", true},
        {"1", true},
        {"123456789", true},
        {"18446744073709551615", true},
        {"18446744073709551616", false},
        {"99999999999999999999", false},
        {"00000000000000000000", true},
        {"000000000000000000000", false},
        {"+1", false},
        {"-1", false},
        {" 1", false},
        {"1 ", false},
        {"1x", false},
        {"x1", false},
        {"1.0", false},
        {"１２３", false}
    };

    for (const auto& testCase : cases) {
        Require(
            OblivionNet::IsValidChallengeNonce(testCase.first) == testCase.second,
            "challenge nonce validation result mismatch");
    }

    std::cout << "Challenge nonce validation tests passed" << std::endl;
    return 0;
}
