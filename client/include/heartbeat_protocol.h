#pragma once

#include <cstdint>
#include <string>

namespace Oblivion {
    // Heartbeat message types
    enum class HbType : uint8_t { Ping = 1, Pong = 2 };

    // Client runtime status bits
    struct ClientStatus {
        bool antiSuspendOk;   // true if no suspend detected
        bool integrityOk;     // true if self-integrity guard passes
    };

    // Wire payload (serialized as: TYPE|SEQ|TS|NONCE|STATUS|HMAC;) for now
    struct HeartbeatMessage {
        HbType type;
        uint32_t seq;           // monotonically increasing sequence
        uint64_t t_send_ms;     // server/client wall-clock in ms
        uint64_t nonce;         // server-provided random for Ping; echoed by Pong
        ClientStatus status;    // client only
        std::string hmac;       // hex string of HMAC-SHA256 over fields
    };

    // Default timing
    struct HeartbeatConfig {
        uint32_t interval_ms = 3000;   // target interval
        uint32_t jitter_ms = 250;      // +- jitter
        uint32_t timeout_ms = 4000;    // receive timeout per hop
        uint32_t max_consecutive_miss = 3; // misses before warning/flag
        uint32_t rtt_warn_ms = 1500;   // sustained RTT limit to warn
    };
}
