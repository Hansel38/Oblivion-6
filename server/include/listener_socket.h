#pragma once

#include "socket_framing.h"

#include <cerrno>

#ifdef _WIN32
#include <ws2tcpip.h>
#else
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace OblivionNet {

    // getaddrinfo() may return multiple IPv4/IPv6 candidates. Do not make the
    // first candidate a single point of failure: try each address until a
    // socket can be created and bound successfully.
    inline bool CreateBoundListener(
        const addrinfo* candidates,
        SocketType& listener,
        int& errorCode) {
#ifdef _WIN32
        listener = INVALID_SOCKET;
#else
        listener = -1;
#endif
        errorCode = 0;

        for (const addrinfo* address = candidates;
             address != nullptr; address = address->ai_next) {
            if (address->ai_addr == nullptr || address->ai_addrlen == 0) {
                errorCode = EINVAL;
                continue;
            }

            const SocketType candidate = ::socket(
                address->ai_family, address->ai_socktype, address->ai_protocol);
#ifdef _WIN32
            if (candidate == INVALID_SOCKET) {
                errorCode = WSAGetLastError();
                continue;
            }

            if (::bind(candidate, address->ai_addr,
                       static_cast<int>(address->ai_addrlen)) == 0) {
                listener = candidate;
                errorCode = 0;
                return true;
            }

            errorCode = WSAGetLastError();
            ::closesocket(candidate);
#else
            if (candidate < 0) {
                errorCode = errno;
                continue;
            }

            // Preserve the Linux server's existing address-reuse setting.
            int reuseAddress = 1;
            (void)::setsockopt(
                candidate, SOL_SOCKET, SO_REUSEADDR,
                &reuseAddress, sizeof(reuseAddress));

            if (::bind(candidate, address->ai_addr,
                       static_cast<socklen_t>(address->ai_addrlen)) == 0) {
                listener = candidate;
                errorCode = 0;
                return true;
            }

            errorCode = errno;
            ::close(candidate);
#endif
        }

        return false;
    }

} // namespace OblivionNet
