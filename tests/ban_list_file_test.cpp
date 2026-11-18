#include "../common/ban_list_file.h"
#include "../common/server_runtime_config.h"

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

namespace {
    void Require(bool condition, const char* description) {
        if (!condition) {
            std::cerr << "FAILED: " << description << std::endl;
            std::abort();
        }
    }
}

int main() {
    namespace fs = std::filesystem;

    const auto uniqueSuffix = std::chrono::steady_clock::now()
        .time_since_epoch().count();
    const fs::path testDirectory = fs::temp_directory_path() /
        ("oblivion-ban-list-test-" + std::to_string(uniqueSuffix));
    fs::create_directories(testDirectory);

    const fs::path missingPath = testDirectory / "missing-bans.txt";
    const fs::path regularPath = testDirectory / "bans.txt";
    const fs::path directoryPath = testDirectory / "directory";
    fs::create_directories(directoryPath);

    Require(!OblivionServer::IsBanListFileAvailable(""),
            "an empty configured path must be unavailable");
    Require(!OblivionServer::IsBanListFileAvailable(missingPath.string()),
            "a missing ban-list must be unavailable, never treated as empty");
    Require(!OblivionServer::IsBanListFileAvailable(directoryPath.string()),
            "a directory must not be accepted as a ban-list file");

    {
        std::ofstream banList(regularPath);
        Require(banList.is_open(), "test ban-list file must be created");
        banList << "# test ban list\n";
        Require(banList.good(), "test ban-list file must be written");
    }

    Require(OblivionServer::IsBanListFileAvailable(regularPath.string()),
            "an existing regular ban-list file must be available");

    const fs::path symlinkPath = testDirectory / "linked-bans.txt";
    std::error_code symlinkError;
    fs::create_symlink(regularPath, symlinkPath, symlinkError);
    Require(!symlinkError, "Linux regression fixture must create a symbolic link");
    Require(!OblivionServer::IsBanListFileAvailable(symlinkPath.string()),
            "a symbolic link to a regular file must not be accepted as the ban list");

    OblivionServer::ServerRuntimeConfig storageConfig;
    storageConfig.banListPath = regularPath.string();
    storageConfig.violationLogPath = (testDirectory / "violations.log").string();
    std::string storageError;
    Require(OblivionServer::ValidateServerStorageFiles(storageConfig, storageError),
            "server startup must accept a real regular ban-list file");
    storageConfig.banListPath = symlinkPath.string();
    Require(!OblivionServer::ValidateServerStorageFiles(storageConfig, storageError),
            "server startup must reject a symbolic-link ban-list path");

    const fs::path logTargetPath = testDirectory / "target.log";
    const fs::path logSymlinkPath = testDirectory / "linked-violations.log";
    {
        std::ofstream logTarget(logTargetPath);
        Require(logTarget.is_open(), "log symlink target must be created");
        logTarget << "do not redirect logs";
        Require(logTarget.good(), "log symlink target must be writable");
    }

    std::error_code logSymlinkError;
    fs::create_symlink(logTargetPath, logSymlinkPath, logSymlinkError);
    Require(!logSymlinkError, "Linux regression fixture must create a log symbolic link");
    Require(!OblivionServer::IsRegularNonSymlinkFileOrMissing(logSymlinkPath.string()),
            "an existing symbolic link must not be accepted as a violation-log target");
    Require(OblivionServer::IsRegularNonSymlinkFileOrMissing(
                (testDirectory / "new-violations.log").string()),
            "a missing violation-log path must remain eligible for creation");

    storageConfig.banListPath = regularPath.string();
    storageConfig.violationLogPath = logSymlinkPath.string();
    Require(!OblivionServer::ValidateServerStorageFiles(storageConfig, storageError),
            "server startup must reject a symbolic-link violation-log path");

    fs::remove_all(testDirectory);
    return 0;
}
