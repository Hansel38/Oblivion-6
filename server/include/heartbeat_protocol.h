#pragma once

#include <cstdint>
#include <string>

namespace Oblivion {
    enum class HbType : uint8_t { Ping = 1, Pong = 2 };

    struct ClientStatus {
        bool antiSuspendOk;
        bool integrityOk;
    };

    struct HeartbeatMessage {
        HbType type;
        uint32_t seq;
        uint64_t t_send_ms;
        uint64_t nonce;
        ClientStatus status;    // ignored for Ping
        std::string hmac;       // hex HMAC-SHA256
    };

    struct HeartbeatConfig {
        uint32_t interval_ms = 3000;
        uint32_t jitter_ms = 250;
        uint32_t timeout_ms = 4000;
        uint32_t max_consecutive_miss = 3;
        uint32_t rtt_warn_ms = 1500;
    };
}
