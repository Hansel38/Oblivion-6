#include "../common/heartbeat_protocol.h"

#include <array>
#include <cassert>
#include <iostream>
#include <string>

int main() {
    struct StatusCase {
        bool antiSuspendOk;
        bool integrityOk;
        const char* serialized;
    };

    const std::array<StatusCase, 4> validStatuses{{
        { false, false, "0|0" },
        { false, true,  "0|1" },
        { true,  false, "1|0" },
        { true,  true,  "1|1" }
    }};

    for (const auto& testCase : validStatuses) {
        const std::string serialized = Oblivion::SerializeClientStatus(
            testCase.antiSuspendOk, testCase.integrityOk);
        assert(serialized == testCase.serialized);
        assert(Oblivion::IsValidClientStatus(serialized));
    }

    const std::array<std::string, 10> invalidStatuses{{
        "", "0", "1", "00", "11", "0|", "|1", "2|1", "1|2", "1||1"
    }};

    for (const auto& status : invalidStatuses) {
        assert(!Oblivion::IsValidClientStatus(status));
    }

    const std::string canonical = Oblivion::BuildPongAuthData(
        17, "123456789", 998877, "1|1", "test-hwid");
    assert(canonical ==
        "PONG:v1:17:123456789:998877:1|1:test-hwid");

    // Every PONG field that is authenticated must change the MAC input when
    // modified. This guards the canonical field order/domain used by all peers.
    assert(canonical != Oblivion::BuildPongAuthData(
        18, "123456789", 998877, "1|1", "test-hwid"));
    assert(canonical != Oblivion::BuildPongAuthData(
        17, "123456788", 998877, "1|1", "test-hwid"));
    assert(canonical != Oblivion::BuildPongAuthData(
        17, "123456789", 998878, "1|1", "test-hwid"));
    assert(canonical != Oblivion::BuildPongAuthData(
        17, "123456789", 998877, "1|0", "test-hwid"));
    assert(canonical != Oblivion::BuildPongAuthData(
        17, "123456789", 998877, "1|1", "changed-hwid"));

    std::cout << "Heartbeat protocol helper tests passed" << std::endl;
    return 0;
}
