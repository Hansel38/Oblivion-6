#pragma once

#include <filesystem>
#include <string>

namespace OblivionServer {

    // A configured ban list is mandatory at runtime. A missing path must not
    // be interpreted as an empty list, because that would allow banned HWIDs.
    inline bool IsBanListFileAvailable(const std::string& path) {
        if (path.empty()) {
            return false;
        }

        std::error_code error;
        const bool regularFile = std::filesystem::is_regular_file(path, error);
        return !error && regularFile;
    }

} // namespace OblivionServer
