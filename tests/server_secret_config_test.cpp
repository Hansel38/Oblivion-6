#include "../server/include/server_secret.h"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <unistd.h>

namespace {
    void Require(bool condition, const char* description) {
        if (!condition) {
            std::cerr << "FAILED: " << description << std::endl;
            std::abort();
        }
    }

    void ClearSecretEnvironment() {
        unsetenv("OBLIVION_SECRET");
        unsetenv("OBLIVION_SECRET_FILE");
    }
}

int main() {
    const std::string validSecret =
        "9f21c6a87b314e5da42f0c19b7e836d5"
        "71a0c4e9286b3d5f";

    ClearSecretEnvironment();
    Require(OblivionServer::GetServerSecret().empty(),
            "missing secret source must fail closed");

    setenv("OBLIVION_SECRET", "", 1);
    Require(OblivionServer::GetServerSecret().empty(),
            "empty environment secret must fail closed");
    ClearSecretEnvironment();

    setenv("OBLIVION_SECRET", validSecret.c_str(), 1);
    setenv("OBLIVION_SECRET_FILE", "/tmp/unused-secret-file", 1);
    Require(OblivionServer::GetServerSecret().empty(),
            "both provisioning sources must be rejected");
    ClearSecretEnvironment();

    setenv("OBLIVION_SECRET", "replace-this-with-a-real-key", 1);
    Require(OblivionServer::GetServerSecret().empty(),
            "placeholder-looking environment secret must be rejected");
    ClearSecretEnvironment();

    setenv("OBLIVION_SECRET", validSecret.c_str(), 1);
    Require(OblivionServer::GetServerSecret() == validSecret,
            "valid environment secret must be returned unchanged");
    ClearSecretEnvironment();

    const auto secretPath =
        std::filesystem::temp_directory_path() /
        ("oblivion-secret-config-" + std::to_string(getpid()) + ".txt");
    {
        std::ofstream secretFile(secretPath, std::ios::binary | std::ios::trunc);
        Require(secretFile.is_open(), "temporary secret fixture must be created");
        secretFile << validSecret << '\n';
    }

    const std::string secretPathText = secretPath.string();
    setenv("OBLIVION_SECRET_FILE", secretPathText.c_str(), 1);
    Require(OblivionServer::GetServerSecret() == validSecret,
            "explicit absolute plaintext secret file must be loaded");
    ClearSecretEnvironment();

    setenv("OBLIVION_SECRET_FILE", "relative-secret.txt", 1);
    Require(OblivionServer::GetServerSecret().empty(),
            "relative secret file paths must be rejected");
    ClearSecretEnvironment();

    std::error_code removeError;
    std::filesystem::remove(secretPath, removeError);
    Require(!removeError, "temporary secret fixture must be removed");

    std::cout << "Server secret configuration tests passed" << std::endl;
    return 0;
}
