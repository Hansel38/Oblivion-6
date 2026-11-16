#pragma once

#include "network_configuration.h"
#include "heartbeat_protocol.h"

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <limits>
#include <string>
#include <string_view>

namespace OblivionServer {
    struct ServerRuntimeConfigInput {
        std::string listenAddress;
        std::string listenPort;
        std::string listenBacklog;
        std::string banListPath;
        std::string violationLogPath;
        std::string maxConcurrentClients;
        std::string requestTimeoutMs;
        std::string heartbeatIntervalMs;
        std::string heartbeatJitterMs;
        std::string heartbeatTimeoutMs;
        std::string heartbeatMaxMiss;
        std::string heartbeatRttWarnMs;
    };

    struct ServerRuntimeConfig {
        std::string listenAddress;
        uint16_t listenPort = 0;
        uint32_t listenBacklog = 0;
        std::string banListPath;
        std::string violationLogPath;
        uint32_t maxConcurrentClients = 0;
        uint32_t requestTimeoutMs = 0;
        Oblivion::HeartbeatConfig heartbeat{};
    };

    inline bool ParseRequiredUInt32(
        std::string_view input, const char* settingName,
        uint32_t& value, std::string& error) {
        if (input.empty()) {
            error = std::string(settingName) + " is required";
            return false;
        }

        uint32_t parsed = 0;
        for (const unsigned char character : input) {
            if (character < '0' || character > '9') {
                error = std::string(settingName) + " must contain decimal digits only";
                return false;
            }

            const uint32_t digit = static_cast<uint32_t>(character - '0');
            if (parsed > ((std::numeric_limits<uint32_t>::max)() - digit) / 10) {
                error = std::string(settingName) + " exceeds the supported integer range";
                return false;
            }
            parsed = parsed * 10 + digit;
        }

        value = parsed;
        return true;
    }

    inline bool IsAbsoluteConfiguredPath(
        const std::string& value, const char* settingName,
        std::string& error) {
        if (value.empty()) {
            error = std::string(settingName) + " is required";
            return false;
        }

        const std::filesystem::path path(value);
        if (!path.is_absolute()) {
            error = std::string(settingName) + " must be an absolute filesystem path";
            return false;
        }
        return true;
    }

    inline bool ValidateServerStorageFiles(
        const ServerRuntimeConfig& config, std::string& error) {
        std::error_code filesystemError;
        if (!std::filesystem::is_regular_file(
                config.banListPath, filesystemError) || filesystemError) {
            error = "OBLIVION_BAN_LIST_PATH must identify an existing regular file";
            return false;
        }

        std::ifstream banList(config.banListPath);
        if (!banList.is_open()) {
            error = "OBLIVION_BAN_LIST_PATH cannot be opened for reading";
            return false;
        }

        std::ofstream violationLog(
            config.violationLogPath, std::ios::out | std::ios::app);
        if (!violationLog.is_open()) {
            error = "OBLIVION_VIOLATION_LOG_PATH cannot be opened for append";
            return false;
        }

        const bool sameFile = std::filesystem::equivalent(
            config.banListPath, config.violationLogPath, filesystemError);
        if (filesystemError || sameFile) {
            error = "OBLIVION_BAN_LIST_PATH and OBLIVION_VIOLATION_LOG_PATH must not resolve to the same file";
            return false;
        }

        return true;
    }

    inline bool ParseServerRuntimeConfig(
        const ServerRuntimeConfigInput& input,
        ServerRuntimeConfig& output,
        std::string& error) {
        error.clear();

        if (input.listenAddress.empty() || input.listenAddress.size() > 253) {
            error = "OBLIVION_LISTEN_ADDRESS is required and must not exceed 253 bytes";
            return false;
        }
        for (const unsigned char character : input.listenAddress) {
            if (character <= 0x20 || character >= 0x7F) {
                error = "OBLIVION_LISTEN_ADDRESS must contain printable ASCII without whitespace";
                return false;
            }
        }

        uint16_t port = 0;
        if (!OblivionNet::ParseTcpPort(input.listenPort, port)) {
            error = "OBLIVION_LISTEN_PORT is required and must be a canonical TCP port from 1 through 65535";
            return false;
        }

        uint32_t listenBacklog = 0;
        if (!ParseRequiredUInt32(input.listenBacklog,
                                 "OBLIVION_LISTEN_BACKLOG",
                                 listenBacklog, error)) {
            return false;
        }
        if (listenBacklog == 0 || listenBacklog > 65535) {
            error = "OBLIVION_LISTEN_BACKLOG must be between 1 and 65535";
            return false;
        }

        if (!IsAbsoluteConfiguredPath(
                input.banListPath, "OBLIVION_BAN_LIST_PATH", error) ||
            !IsAbsoluteConfiguredPath(
                input.violationLogPath, "OBLIVION_VIOLATION_LOG_PATH", error)) {
            return false;
        }

        const std::filesystem::path banPath =
            std::filesystem::path(input.banListPath).lexically_normal();
        const std::filesystem::path logPath =
            std::filesystem::path(input.violationLogPath).lexically_normal();
        if (banPath == logPath) {
            error = "OBLIVION_BAN_LIST_PATH and OBLIVION_VIOLATION_LOG_PATH must identify different files";
            return false;
        }

        uint32_t maxClients = 0;
        uint32_t requestTimeout = 0;
        uint32_t heartbeatInterval = 0;
        uint32_t heartbeatJitter = 0;
        uint32_t heartbeatTimeout = 0;
        uint32_t heartbeatMaxMiss = 0;
        uint32_t heartbeatRttWarn = 0;

        if (!ParseRequiredUInt32(input.maxConcurrentClients,
                                 "OBLIVION_MAX_CONCURRENT_CLIENTS",
                                 maxClients, error) ||
            !ParseRequiredUInt32(input.requestTimeoutMs,
                                 "OBLIVION_REQUEST_TIMEOUT_MS",
                                 requestTimeout, error) ||
            !ParseRequiredUInt32(input.heartbeatIntervalMs,
                                 "OBLIVION_HB_INTERVAL_MS",
                                 heartbeatInterval, error) ||
            !ParseRequiredUInt32(input.heartbeatJitterMs,
                                 "OBLIVION_HB_JITTER_MS",
                                 heartbeatJitter, error) ||
            !ParseRequiredUInt32(input.heartbeatTimeoutMs,
                                 "OBLIVION_HB_TIMEOUT_MS",
                                 heartbeatTimeout, error) ||
            !ParseRequiredUInt32(input.heartbeatMaxMiss,
                                 "OBLIVION_HB_MAX_MISS",
                                 heartbeatMaxMiss, error) ||
            !ParseRequiredUInt32(input.heartbeatRttWarnMs,
                                 "OBLIVION_HB_RTT_WARN_MS",
                                 heartbeatRttWarn, error)) {
            return false;
        }

        if (maxClients == 0 || maxClients > 1024) {
            error = "OBLIVION_MAX_CONCURRENT_CLIENTS must be between 1 and 1024";
            return false;
        }
        if (requestTimeout < 100 || requestTimeout > 120000) {
            error = "OBLIVION_REQUEST_TIMEOUT_MS must be between 100 and 120000";
            return false;
        }
        if (heartbeatInterval < 100 || heartbeatInterval > 60000 ||
            heartbeatJitter > 10000 ||
            heartbeatTimeout < 250 || heartbeatTimeout > 120000 ||
            heartbeatMaxMiss < 1 || heartbeatMaxMiss > 10 ||
            heartbeatRttWarn > 60000) {
            error = "Heartbeat configuration is outside the supported safety bounds";
            return false;
        }

        output.listenAddress = input.listenAddress;
        output.listenPort = port;
        output.listenBacklog = listenBacklog;
        output.banListPath = banPath.string();
        output.violationLogPath = logPath.string();
        output.maxConcurrentClients = maxClients;
        output.requestTimeoutMs = requestTimeout;
        output.heartbeat.interval_ms = heartbeatInterval;
        output.heartbeat.jitter_ms = heartbeatJitter;
        output.heartbeat.timeout_ms = heartbeatTimeout;
        output.heartbeat.max_consecutive_miss = heartbeatMaxMiss;
        output.heartbeat.rtt_warn_ms = heartbeatRttWarn;
        return true;
    }
}
