#include "socket_framing.h"

#include <cassert>
#include <chrono>
#include <iostream>
#include <string>
#include <thread>

#ifndef _WIN32
#include <sys/socket.h>
#include <unistd.h>
#endif

#ifndef _WIN32
namespace {
    void CreatePair(int sockets[2]) {
        const int result = socketpair(AF_UNIX, SOCK_STREAM, 0, sockets);
        assert(result == 0);
    }

    void ClosePair(const int sockets[2]) {
        close(sockets[0]);
        close(sockets[1]);
    }

    void SendPayload(int socket, const std::string& payload) {
        assert(OblivionNet::SendAll(socket, payload.data(), payload.size()));
    }

    void TestFragmentedFrame() {
        int sockets[2]{};
        CreatePair(sockets);

        const std::string expected = "PING:v1:123;";
        bool senderSucceeded = true;
        std::thread sender([&]() {
            for (const char ch : expected) {
                if (!OblivionNet::SendAll(sockets[1], &ch, 1)) {
                    senderSucceeded = false;
                    return;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(2));
            }
        });

        std::string pending;
        std::string frame;
        const bool received =
            OblivionNet::ReceiveFrame(sockets[0], pending, frame, 2000, 64);

        sender.join();
        assert(senderSucceeded);
        assert(received);
        assert(frame == expected);
        assert(pending.empty());
        ClosePair(sockets);
    }

    void TestCoalescedFramesPreserveRemainder() {
        int sockets[2]{};
        CreatePair(sockets);
        SendPayload(sockets[1], "FIRST;SECOND;");

        std::string pending;
        std::string frame;
        assert(OblivionNet::ReceiveFrame(sockets[0], pending, frame, 1000, 32));
        assert(frame == "FIRST;");
        assert(pending == "SECOND;");

        frame.clear();
        assert(OblivionNet::ReceiveFrame(sockets[0], pending, frame, 1000, 32));
        assert(frame == "SECOND;");
        assert(pending.empty());
        ClosePair(sockets);
    }

    void TestMaximumFrameBoundaries() {
        {
            int sockets[2]{};
            CreatePair(sockets);
            SendPayload(sockets[1], "AB;");
            std::string pending;
            std::string frame;
            assert(OblivionNet::ReceiveFrame(sockets[0], pending, frame, 1000, 3));
            assert(frame == "AB;");
            ClosePair(sockets);
        }

        {
            int sockets[2]{};
            CreatePair(sockets);
            SendPayload(sockets[1], "ABC;");
            std::string pending;
            std::string frame;
            assert(!OblivionNet::ReceiveFrame(sockets[0], pending, frame, 1000, 3));
            ClosePair(sockets);
        }

        {
            int sockets[2]{};
            CreatePair(sockets);
            SendPayload(sockets[1], "ABCD");
            std::string pending;
            std::string frame;
            assert(!OblivionNet::ReceiveFrame(sockets[0], pending, frame, 1000, 3));
            ClosePair(sockets);
        }
    }

    void TestTimeoutAndPeerClose() {
        {
            int sockets[2]{};
            CreatePair(sockets);
            std::string pending;
            std::string frame;
            const auto start = std::chrono::steady_clock::now();
            assert(!OblivionNet::ReceiveFrame(sockets[0], pending, frame, 30, 16));
            const auto elapsed = std::chrono::steady_clock::now() - start;
            assert(elapsed < std::chrono::seconds(1));
            ClosePair(sockets);
        }

        {
            int sockets[2]{};
            CreatePair(sockets);
            shutdown(sockets[1], SHUT_WR);
            std::string pending;
            std::string frame;
            assert(!OblivionNet::ReceiveFrame(sockets[0], pending, frame, 1000, 16));
            ClosePair(sockets);
        }
    }

    void TestZeroLengthSend() {
        int sockets[2]{};
        CreatePair(sockets);
        const std::string empty;
        assert(OblivionNet::SendAll(sockets[0], empty.data(), empty.size()));
        ClosePair(sockets);
    }
}
#endif

int main() {
#ifdef _WIN32
    std::cout << "TCP socket framing tests require POSIX socketpair in this CI target"
              << std::endl;
#else
    TestFragmentedFrame();
    TestCoalescedFramesPreserveRemainder();
    TestMaximumFrameBoundaries();
    TestTimeoutAndPeerClose();
    TestZeroLengthSend();
    std::cout << "TCP socket framing tests passed" << std::endl;
#endif
    return 0;
}
