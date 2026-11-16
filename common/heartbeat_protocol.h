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
        ClientStatus status;
        std::string hmac;
    };

    // No implicit timing policy is provided here. The server must load every
    // field from its required deployment configuration; the client initializes
    // this type from the server-authenticated session negotiation.
    struct HeartbeatConfig {
        uint32_t interval_ms;
        uint32_t jitter_ms;
        uint32_t timeout_ms;
        uint32_t max_consecutive_miss;
        uint32_t rtt_warn_ms;
    };

    // A heartbeat frame must belong to the next exchange in this session.
    // uint32_t wraparound is intentional and shared by both peers.
    inline bool IsExpectedHeartbeatSequence(
        uint32_t receivedSequence, uint32_t expectedSequence) noexcept {
        return receivedSequence == expectedSequence;
    }

    inline std::string SerializeClientStatus(bool antiSuspendOk, bool integrityOk) {
        return std::string(antiSuspendOk ? "1" : "0") + "|" +
               (integrityOk ? "1" : "0");
    }

    inline bool IsValidClientStatus(const std::string& status) {
        return status.size() == 3 &&
               (status[0] == '0' || status[0] == '1') &&
               status[1] == '|' &&
               (status[2] == '0' || status[2] == '1');
    }

    // Canonical authenticated PONG data shared by the Windows client,
    // Windows server, and Linux server. The TCP frame envelope stays unchanged.
    inline std::string BuildPongAuthData(
        uint32_t seq,
        const std::string& clientTimestamp,
        uint64_t nonce,
        const std::string& status,
        const std::string& hwid) {
        return "PONG:v1:" + std::to_string(seq) + ":" + clientTimestamp + ":" +
               std::to_string(nonce) + ":" + status + ":" + hwid;
    }
}
