#pragma once

#include <algorithm>
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

    // Bound per-session jitter so the negotiated interval remains inside the
    // client/server supported range and never needs a protocol-format change.
    inline uint32_t GetHeartbeatJitterLimit(
        uint32_t interval_ms, uint32_t jitter_ms) noexcept {
        constexpr uint32_t kMinimumIntervalMs = 100;
        constexpr uint32_t kMaximumIntervalMs = 60000;
        if (interval_ms < kMinimumIntervalMs ||
            interval_ms > kMaximumIntervalMs) {
            return 0;
        }

        const uint32_t lowerHeadroom = interval_ms - kMinimumIntervalMs;
        const uint32_t upperHeadroom = kMaximumIntervalMs - interval_ms;
        return (std::min)(jitter_ms, (std::min)(lowerHeadroom, upperHeadroom));
    }

    // Apply one symmetric, bounded offset when a session is negotiated. The
    // server authenticates and sends this exact interval in the existing
    // SESSION/HB_CONFIG frames; client timeout handling therefore stays aligned.
    inline uint32_t ApplyHeartbeatIntervalJitter(
        uint32_t interval_ms, uint32_t jitter_ms,
        int32_t requestedOffsetMs) noexcept {
        const uint32_t jitterLimit =
            GetHeartbeatJitterLimit(interval_ms, jitter_ms);
        const int64_t lowerOffset = -static_cast<int64_t>(jitterLimit);
        const int64_t upperOffset = static_cast<int64_t>(jitterLimit);
        int64_t offset = static_cast<int64_t>(requestedOffsetMs);
        if (offset < lowerOffset) offset = lowerOffset;
        if (offset > upperOffset) offset = upperOffset;

        return static_cast<uint32_t>(
            static_cast<int64_t>(interval_ms) + offset);
    }

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
