#include "../common/network_configuration.h"

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
        {"", false}, {"0", false}, {"1", true}, {"443", true},
        {"65535", true}, {"65536", false}, {"-1", false},
        {"+1", false}, {" 1", false}, {"1 ", false}, {"1.0", false},
        {"abc", false}, {"000001", false}
    };

    for (const auto& testCase : cases) {
        uint16_t port = 0;
        Require(OblivionNet::ParseTcpPort(testCase.first, port) == testCase.second,
                "TCP port validation result mismatch");
        if (testCase.second) {
            Require(OblivionNet::FormatTcpPort(port) == std::to_string(port),
                    "TCP port formatting result mismatch");
        }
    }

    std::cout << "Network configuration tests passed" << std::endl;
    return 0;
}
