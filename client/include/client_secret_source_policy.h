#pragma once

#include <cstdint>

namespace Oblivion {
    enum class ClientSecretEnvironmentState : uint8_t {
        ValuePresent,
        NotSet,
        ExplicitlyEmpty,
        QueryFailed
    };

    // Keep source selection separate from the Win32 API so its fail-closed
    // behavior can be regression-tested on every CI platform.
    inline ClientSecretEnvironmentState ClassifyClientSecretEnvironment(
        bool valuePresent,
        bool variableNotFound,
        bool lastErrorSuccess) noexcept {
        if (valuePresent) return ClientSecretEnvironmentState::ValuePresent;
        if (variableNotFound) return ClientSecretEnvironmentState::NotSet;
        if (lastErrorSuccess) return ClientSecretEnvironmentState::ExplicitlyEmpty;
        return ClientSecretEnvironmentState::QueryFailed;
    }

    inline bool ShouldLoadClientSecretFile(
        ClientSecretEnvironmentState state) noexcept {
        // A file fallback is permitted only when the environment variable is
        // genuinely absent. Empty values and API errors must not select stale
        // credentials from disk.
        return state == ClientSecretEnvironmentState::NotSet;
    }
}
