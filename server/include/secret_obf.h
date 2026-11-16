#pragma once

#include <string>

// Loads the server's explicitly provisioned secret. This module does not
// embed, encode, or obfuscate credentials.
namespace OblivionServer {
    std::string GetServerSecret();
}
