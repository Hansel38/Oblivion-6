#include "../common/ban_list_file.h"

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

    fs::remove_all(testDirectory);
    return 0;
}
