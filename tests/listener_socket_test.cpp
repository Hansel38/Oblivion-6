#include "../server/include/listener_socket.h"

#include <cstdlib>
#include <cstring>
#include <iostream>

#ifndef _WIN32
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace {
    void Require(bool condition, const char* description) {
        if (!condition) {
            std::cerr << "FAILED: " << description << std::endl;
            std::abort();
        }
    }
}

int main() {
#ifdef _WIN32
    // The listener helper is compiled by the Windows solution. This runtime
    // fixture currently runs in the Linux CI job where ephemeral local binds
    // are available without additional service setup.
    return 0;
#else
    const int blocker = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    Require(blocker >= 0, "blocker socket must be created");

    sockaddr_in blockedAddress{};
    blockedAddress.sin_family = AF_INET;
    blockedAddress.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    blockedAddress.sin_port = 0;
    Require(::bind(blocker, reinterpret_cast<sockaddr*>(&blockedAddress),
                   sizeof(blockedAddress)) == 0,
            "blocker socket must bind to an ephemeral loopback port");

    socklen_t blockedAddressLength = sizeof(blockedAddress);
    Require(::getsockname(blocker,
                          reinterpret_cast<sockaddr*>(&blockedAddress),
                          &blockedAddressLength) == 0,
            "blocker socket address must be readable");
    Require(::listen(blocker, 1) == 0, "blocker socket must listen");

    sockaddr_in fallbackAddress{};
    fallbackAddress.sin_family = AF_INET;
    fallbackAddress.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    fallbackAddress.sin_port = 0;

    addrinfo first{};
    first.ai_family = AF_INET;
    first.ai_socktype = SOCK_STREAM;
    first.ai_protocol = IPPROTO_TCP;
    first.ai_addr = reinterpret_cast<sockaddr*>(&blockedAddress);
    first.ai_addrlen = sizeof(blockedAddress);

    addrinfo second{};
    second.ai_family = AF_INET;
    second.ai_socktype = SOCK_STREAM;
    second.ai_protocol = IPPROTO_TCP;
    second.ai_addr = reinterpret_cast<sockaddr*>(&fallbackAddress);
    second.ai_addrlen = sizeof(fallbackAddress);
    first.ai_next = &second;

    OblivionNet::SocketType listener = -1;
    int errorCode = 0;
    const bool bound = OblivionNet::CreateBoundListener(
        &first, listener, errorCode);

    Require(bound, "the helper must continue after the first bind candidate fails");
    Require(listener >= 0, "a valid listener socket must be returned");
    Require(errorCode == 0, "successful fallback must clear the previous candidate error");
    Require(::listen(listener, 1) == 0, "the fallback socket must be listenable");

    ::close(listener);
    ::close(blocker);
    return 0;
#endif
}
