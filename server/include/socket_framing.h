#pragma once

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>

#ifdef _WIN32
#include <winsock2.h>
#include <bcrypt.h>
#else
#include <openssl/rand.h>
#include <cerrno>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#endif

namespace OblivionNet {

#ifdef _WIN32
    using SocketType = SOCKET;
#else
    using SocketType = int;
#endif

    inline bool GenerateSecureNonce(uint64_t& value) {
        value = 0;
#ifdef _WIN32
        return BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(&value),
                               static_cast<ULONG>(sizeof(value)),
                               BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0;
#else
        return RAND_bytes(reinterpret_cast<unsigned char*>(&value),
                          static_cast<int>(sizeof(value))) == 1;
#endif
    }

    inline bool SendAll(SocketType socket, const char* data, size_t length) {
        size_t offset = 0;
        while (offset < length) {
            const size_t remaining = length - offset;
            const int chunk = static_cast<int>((std::min)(
                remaining, static_cast<size_t>((std::numeric_limits<int>::max)())));

#ifdef _WIN32
            const int sent = send(socket, data + offset, chunk, 0);
#else
#ifdef MSG_NOSIGNAL
            const ssize_t sent = send(socket, data + offset, static_cast<size_t>(chunk), MSG_NOSIGNAL);
#else
            const ssize_t sent = send(socket, data + offset, static_cast<size_t>(chunk), 0);
#endif
#endif
            if (sent < 0) {
#ifndef _WIN32
                if (errno == EINTR) continue;
#endif
                return false;
            }
            if (sent == 0) return false;
            offset += static_cast<size_t>(sent);
        }
        return true;
    }

    // Read one semicolon-terminated frame from TCP without assuming recv() boundaries.
    // Any bytes after the frame remain in pending for the next protocol read.
    inline bool ReceiveFrame(SocketType socket, std::string& pending,
                             std::string& frame, uint32_t timeoutMs,
                             size_t maxFrameSize = 4096) {
        const auto deadline = std::chrono::steady_clock::now() +
                              std::chrono::milliseconds(timeoutMs);

        for (;;) {
            const size_t delimiter = pending.find(';');
            if (delimiter != std::string::npos) {
                if (delimiter + 1 > maxFrameSize) return false;
                frame.assign(pending, 0, delimiter + 1);
                pending.erase(0, delimiter + 1);
                return true;
            }

            if (pending.size() >= maxFrameSize) return false;

            const auto now = std::chrono::steady_clock::now();
            if (now >= deadline) return false;
            const auto remainingUs =
                std::chrono::duration_cast<std::chrono::microseconds>(deadline - now).count();

#ifdef _WIN32
            timeval timeout{};
            timeout.tv_sec = static_cast<long>(remainingUs / 1000000);
            timeout.tv_usec = static_cast<long>(remainingUs % 1000000);
            fd_set readSet;
            FD_ZERO(&readSet);
            FD_SET(socket, &readSet);
            const int ready = select(0, &readSet, nullptr, nullptr, &timeout);
            if (ready <= 0) return false;
#else
            const long long remainingMs = (remainingUs + 999) / 1000;
            const int pollTimeout = static_cast<int>((std::min)(
                remainingMs, static_cast<long long>((std::numeric_limits<int>::max)())));
            pollfd descriptor{};
            descriptor.fd = socket;
            descriptor.events = POLLIN;
            const int ready = poll(&descriptor, 1, pollTimeout);
            if (ready < 0) {
                if (errno == EINTR) continue;
                return false;
            }
            if (ready == 0 || (descriptor.revents & POLLNVAL) != 0) return false;
#endif

            char buffer[512];
#ifdef _WIN32
            const int received = recv(socket, buffer, static_cast<int>(sizeof(buffer)), 0);
#else
            const ssize_t received = recv(socket, buffer, sizeof(buffer), 0);
#endif
            if (received <= 0) {
#ifndef _WIN32
                if (received < 0 && errno == EINTR) continue;
#endif
                return false;
            }

            pending.append(buffer, static_cast<size_t>(received));
            if (pending.size() > maxFrameSize &&
                pending.find(';') == std::string::npos) {
                return false;
            }
        }
    }
}
