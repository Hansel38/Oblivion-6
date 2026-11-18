#pragma once

#include <filesystem>
#include <string>
#include <system_error>

namespace OblivionServer {

    // A configured ban list is mandatory at runtime. A missing path must not
    // be interpreted as an empty list, because that would allow banned HWIDs.
    inline bool IsBanListFileAvailable(const std::string& path) {
        if (path.empty()) {
            return false;
        }

        std::error_code error;
        // symlink_status inspects the configured path itself instead of
        // following a symlink to some other file. A ban-list symlink can
        // otherwise redirect reads to an empty or attacker-controlled file.
        const std::filesystem::file_status status =
            std::filesystem::symlink_status(path, error);
        return !error && std::filesystem::is_regular_file(status);
    }

} // namespace OblivionServer
