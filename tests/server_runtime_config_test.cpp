#include "../common/server_runtime_config.h"

#include <cstdlib>
#include <iostream>
#include <string>

namespace {
    void Require(bool condition, const char* description) {
        if (!condition) {
            std::cerr << "FAILED: " << description << std::endl;
            std::abort();
        }
    }

    OblivionServer::ServerRuntimeConfigInput ValidInput() {
        OblivionServer::ServerRuntimeConfigInput input;
        input.listenAddress = "127.0.0.1";
        input.listenPort = "61234";
        input.banListPath = "/var/lib/oblivion/bans.txt";
        input.violationLogPath = "/var/log/oblivion/violations.log";
        input.maxConcurrentClients = "48";
        input.requestTimeoutMs = "7000";
        input.heartbeatIntervalMs = "3500";
        input.heartbeatJitterMs = "200";
        input.heartbeatTimeoutMs = "5000";
        input.heartbeatMaxMiss = "4";
        input.heartbeatRttWarnMs = "1800";
        return input;
    }
}

int main() {
    OblivionServer::ServerRuntimeConfig output;
    std::string error;

    const auto valid = ValidInput();
    Require(OblivionServer::ParseServerRuntimeConfig(valid, output, error),
            "complete valid configuration must parse");
    Require(output.listenPort == 61234, "listen port must be parsed");
    Require(output.maxConcurrentClients == 48, "max clients must be parsed");
    Require(output.requestTimeoutMs == 7000, "request timeout must be parsed");
    Require(output.heartbeat.interval_ms == 3500 &&
            output.heartbeat.jitter_ms == 200 &&
            output.heartbeat.timeout_ms == 5000 &&
            output.heartbeat.max_consecutive_miss == 4 &&
            output.heartbeat.rtt_warn_ms == 1800,
            "all heartbeat values must be taken from the supplied configuration");

    auto missingHeartbeat = valid;
    missingHeartbeat.heartbeatJitterMs.clear();
    Require(!OblivionServer::ParseServerRuntimeConfig(
                missingHeartbeat, output, error),
            "missing heartbeat setting must fail instead of using a fallback");
    Require(error.find("OBLIVION_HB_JITTER_MS") != std::string::npos,
            "missing heartbeat error must identify the setting");

    auto missingStorage = valid;
    missingStorage.banListPath.clear();
    Require(!OblivionServer::ParseServerRuntimeConfig(
                missingStorage, output, error),
            "missing ban-list path must fail");

    auto relativeLogPath = valid;
    relativeLogPath.violationLogPath = "violations.log";
    Require(!OblivionServer::ParseServerRuntimeConfig(
                relativeLogPath, output, error),
            "relative log paths must fail");

    auto sharedStoragePath = valid;
    sharedStoragePath.violationLogPath = sharedStoragePath.banListPath;
    Require(!OblivionServer::ParseServerRuntimeConfig(
                sharedStoragePath, output, error),
            "ban-list and violation-log paths must be different");

    auto invalidPort = valid;
    invalidPort.listenPort = "0";
    Require(!OblivionServer::ParseServerRuntimeConfig(
                invalidPort, output, error),
            "invalid listener port must fail");

    auto zeroClients = valid;
    zeroClients.maxConcurrentClients = "0";
    Require(!OblivionServer::ParseServerRuntimeConfig(
                zeroClients, output, error),
            "zero max-client count must fail");

    auto malformedInteger = valid;
    malformedInteger.requestTimeoutMs = "7000ms";
    Require(!OblivionServer::ParseServerRuntimeConfig(
                malformedInteger, output, error),
            "integer settings must reject suffixes and malformed values");

    std::cout << "Server runtime configuration tests passed" << std::endl;
    return 0;
}
