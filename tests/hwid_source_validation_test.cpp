#include "../client/include/hwid_source_validation.h"

#include <cstdlib>
#include <iostream>
#include <string>
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
    const std::vector<std::string> unavailableValues = {
        "",
        " ",
        "\t\r\n",
        "UNKNOWN",
        "unknown",
        "N/A",
        "None",
        "NULL",
        "Not Applicable",
        "Not Available",
        "Not Specified",
        "Not Set",
        "No Data",
        "No Serial Number",
        "Default",
        "Default String",
        "System Serial Number",
        "To Be Filled",
        "To Be Filled By O.E.M.",
        "00000000-0000-0000-0000-000000000000",
        "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF",
        "00000000000000000000",
        "FFFFFFFFFFFFFFFFFFFF"
    };

    for (const auto& value : unavailableValues) {
        Require(!Oblivion::IsDeviceSpecificWmiValueAvailable(value),
                "known WMI/firmware placeholder must be unavailable");
    }

    const std::vector<std::string> availableValues = {
        "ABCDEF0123456789",
        "03000200-0400-0500-0006-000700080009",
        "SN-0000000000000001",
        "00000001-0000-0000-0000-000000000000",
        "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFE",
        "OEM-BOARD-REV-2"
    };

    for (const auto& value : availableValues) {
        Require(Oblivion::IsDeviceSpecificWmiValueAvailable(value),
                "real or mixed WMI value must remain available");
    }

    std::cout << "HWID WMI source validation tests passed" << std::endl;
    return 0;
}
