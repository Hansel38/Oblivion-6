#include "socket_framing.h"

#include <chrono>
#include <cstdlib>
#include <iostream>
#include <string>
#include <thread>

#ifndef _WIN32
#include <sys/socket.h>
#include <unistd.h>
#endif

#ifndef _WIN32
namespace {
    void Require(bool condition, const char* message) {
        if (!condition) {
            std::cerr << "FAILED: " << message << std::endl;
            std::abort();
        }
    }

    void CreatePair(int sockets[2]) {
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0) {
            std::cerr << "socketpair failed" << std::endl;
            std::abort();
        }
    }

    void ClosePair(const int sockets[2]) {
        close(sockets[0]);
        close(sockets[1]);
    }

    void SendPayload(int socket, const std::string& payload) {
        Require(
            OblivionNet::SendAll(socket, payload.data(), payload.size()),
            "SendAll should transmit the complete payload");
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
        Require(senderSucceeded, "fragmented sender should complete");
        Require(received, "fragmented frame should be reconstructed");
        Require(frame == expected, "fragmented frame content should match");
        Require(pending.empty(), "fragmented frame should leave no remainder");
        ClosePair(sockets);
    }

    void TestCoalescedFramesPreserveRemainder() {
        int sockets[2]{};
        CreatePair(sockets);
        SendPayload(sockets[1], "FIRST;SECOND;");

        std::string pending;
        std::string frame;
        Require(
            OblivionNet::ReceiveFrame(sockets[0], pending, frame, 1000, 32),
            "first coalesced frame should be read");
        Require(frame == "FIRST;", "first frame content should match");
        Require(pending == "SECOND;", "second coalesced frame should remain pending");

        frame.clear();
        Require(
            OblivionNet::ReceiveFrame(sockets[0], pending, frame, 1000, 32),
            "second coalesced frame should be read from pending data");
        Require(frame == "SECOND;", "second frame content should match");
        Require(pending.empty(), "pending buffer should be empty after both frames");
        ClosePair(sockets);
    }

    void TestMaximumFrameBoundaries() {
        {
            int sockets[2]{};
            CreatePair(sockets);
            SendPayload(sockets[1], "AB;");
            std::string pending;
            std::string frame;
            Require(
                OblivionNet::ReceiveFrame(sockets[0], pending, frame, 1000, 3),
                "frame exactly at maximum size should be accepted");
            Require(frame == "AB;", "maximum-size frame content should match");
            ClosePair(sockets);
        }

        {
            int sockets[2]{};
            CreatePair(sockets);
            SendPayload(sockets[1], "ABC;");
            std::string pending;
            std::string frame;
            Require(
                !OblivionNet::ReceiveFrame(sockets[0], pending, frame, 1000, 3),
                "frame larger than maximum size should be rejected");
            ClosePair(sockets);
        }

        {
            int sockets[2]{};
            CreatePair(sockets);
            SendPayload(sockets[1], "ABCD");
            std::string pending;
            std::string frame;
            Require(
                !OblivionNet::ReceiveFrame(sockets[0], pending, frame, 1000, 3),
                "oversized unterminated frame should be rejected");
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
            const bool received =
                OblivionNet::ReceiveFrame(sockets[0], pending, frame, 30, 16);
            const auto elapsed = std::chrono::steady_clock::now() - start;
            Require(!received, "empty socket should time out");
            Require(elapsed < std::chrono::seconds(1), "timeout should remain bounded");
            ClosePair(sockets);
        }

        {
            int sockets[2]{};
            CreatePair(sockets);
            shutdown(sockets[1], SHUT_WR);
            std::string pending;
            std::string frame;
            Require(
                !OblivionNet::ReceiveFrame(sockets[0], pending, frame, 1000, 16),
                "peer close before delimiter should fail the frame read");
            ClosePair(sockets);
        }
    }

    void TestZeroLengthSend() {
        int sockets[2]{};
        CreatePair(sockets);
        const std::string empty;
        Require(
            OblivionNet::SendAll(sockets[0], empty.data(), empty.size()),
            "zero-length SendAll should succeed without sending");
        ClosePair(sockets);
    }
}
#endif

int main() {
#ifdef _WIN32
    std::cout << "TCP socket framing tests run on the Linux socketpair CI target"
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
