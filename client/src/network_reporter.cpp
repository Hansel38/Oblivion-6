#include "pch.h"
#include "network_reporter.h"
#include "heartbeat_protocol.h"
#include "hwid_generator.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <thread>
#include <chrono>
#include <algorithm>
#include <cctype>
#include <random>
#include <limits>
#include <stdexcept>
#include <bcrypt.h>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Bcrypt.lib")

extern void ReportViolationAndExit(const std::wstring& message, const std::string& type, const std::string& details);

#ifndef BCRYPT_ALG_HANDLE_HMAC
#define BCRYPT_ALG_HANDLE_HMAC 0x00000008
#endif

namespace Oblivion {

    static bool SendAll(SOCKET socket, const std::string& data);
    static bool ReceiveFrame(SOCKET socket, std::string& pending,
                             std::string& frame, DWORD timeoutMs, size_t maxSize);

    static std::string HmacSha256(const std::string& key, const std::string& data);

    static bool ConstantTimeEquals(const std::string& left, const std::string& right) {
        if (left.size() != 64 || right.size() != 64) return false;
        unsigned char difference = 0;
        for (size_t i = 0; i < left.size(); ++i) {
            difference |= static_cast<unsigned char>(left[i] ^ right[i]);
        }
        return difference == 0;
    }

    static bool VerifyControlFrame(
        const std::string& frame, const std::string& status,
        const std::string& secret, const std::string& hwid,
        const std::string& challengeNonce) {
        const std::string prefix = status + ":";
        if (frame.size() != prefix.size() + 65 ||
            frame.compare(0, prefix.size(), prefix) != 0 ||
            frame.back() != ';') {
            return false;
        }

        const std::string receivedMac =
            frame.substr(prefix.size(), frame.size() - prefix.size() - 1);
        const std::string expectedMac = HmacSha256(
            secret, "RESPONSE:" + status + ":" + hwid + ":" + challengeNonce);
        return ConstantTimeEquals(expectedMac, receivedMac);
    }

    static std::string BuildRequestAuthData(
        const std::string& type, const std::string& details,
        const std::string& hwid, const std::string& challengeNonce) {
        return "REQUEST:" + type + ":" + std::to_string(details.size()) + ":" +
               details + ":" + hwid + ":" + challengeNonce;
    }

    static bool BeginAuthenticatedRequest(
        SOCKET socket, const std::string& hwid, const std::string& secret,
        std::string& pending, std::string& challengeNonce) {
        challengeNonce.clear();
        if (hwid.empty() || !SendAll(socket, "HELLO:" + hwid + ";")) {
            return false;
        }

        std::string challengeFrame;
        if (!ReceiveFrame(socket, pending, challengeFrame, 3000, 512) ||
            !pending.empty() ||
            challengeFrame.rfind("CHALLENGE:", 0) != 0 ||
            challengeFrame.back() != ';') {
            return false;
        }

        const std::string payload = challengeFrame.substr(
            strlen("CHALLENGE:"),
            challengeFrame.size() - strlen("CHALLENGE:") - 1);
        const size_t separator = payload.find(':');
        if (separator == std::string::npos ||
            payload.find(':', separator + 1) != std::string::npos) {
            return false;
        }

        const std::string nonceText = payload.substr(0, separator);
        const std::string serverMac = payload.substr(separator + 1);
        if (nonceText.empty() || nonceText.size() > 20 ||
            !std::all_of(nonceText.begin(), nonceText.end(),
                [](unsigned char c) { return c >= '0' && c <= '9'; })) {
            return false;
        }

        try {
            size_t parsed = 0;
            std::stoull(nonceText, &parsed, 10);
            if (parsed != nonceText.size()) return false;
        } catch (...) {
            return false;
        }

        const std::string expectedMac =
            HmacSha256(secret, "CHALLENGE:" + hwid + ":" + nonceText);
        if (!ConstantTimeEquals(expectedMac, serverMac)) {
            return false;
        }

        challengeNonce = nonceText;
        return true;
    }

    static bool SendAll(SOCKET socket, const std::string& data) {
        size_t offset = 0;
        while (offset < data.size()) {
            const size_t remaining = data.size() - offset;
            const int chunk = static_cast<int>((std::min)(remaining,
                static_cast<size_t>((std::numeric_limits<int>::max)())));
            const int sent = send(socket, data.data() + offset, chunk, 0);
            if (sent <= 0) return false;
            offset += static_cast<size_t>(sent);
        }
        return true;
    }

    static bool ConnectWithDeadline(
        SOCKET socket, const sockaddr* address, int addressLength,
        const std::chrono::steady_clock::time_point& deadline) {
        u_long nonBlocking = 1;
        if (ioctlsocket(socket, FIONBIO, &nonBlocking) == SOCKET_ERROR) {
            return false;
        }

        bool connected = false;
        const int connectResult = connect(socket, address, addressLength);
        if (connectResult == 0) {
            connected = true;
        }
        else {
            const int connectError = WSAGetLastError();
            if (connectError == WSAEWOULDBLOCK ||
                connectError == WSAEINPROGRESS ||
                connectError == WSAEALREADY) {
                const auto now = std::chrono::steady_clock::now();
                if (now < deadline) {
                    const auto remainingUs =
                        std::chrono::duration_cast<std::chrono::microseconds>(deadline - now).count();
                    timeval timeout{};
                    timeout.tv_sec = static_cast<long>(remainingUs / 1000000);
                    timeout.tv_usec = static_cast<long>(remainingUs % 1000000);

                    fd_set writeSet;
                    fd_set exceptSet;
                    FD_ZERO(&writeSet);
                    FD_ZERO(&exceptSet);
                    FD_SET(socket, &writeSet);
                    FD_SET(socket, &exceptSet);

                    const int selectResult = select(0, nullptr, &writeSet, &exceptSet, &timeout);
                    if (selectResult > 0 &&
                        (FD_ISSET(socket, &writeSet) || FD_ISSET(socket, &exceptSet))) {
                        int socketError = 0;
                        int errorLength = sizeof(socketError);
                        connected = getsockopt(socket, SOL_SOCKET, SO_ERROR,
                            reinterpret_cast<char*>(&socketError), &errorLength) == 0 &&
                            socketError == 0;
                    }
                }
            }
        }

        // Restore the blocking mode expected by the existing send/receive code.
        u_long blocking = 0;
        if (ioctlsocket(socket, FIONBIO, &blocking) == SOCKET_ERROR) {
            return false;
        }
        return connected;
    }

    struct DnsResolveContext {
        OVERLAPPED overlapped{};
        ADDRINFOEXW* results = nullptr;
        HANDLE completionEvent = nullptr;
        DWORD completionError = WSANO_RECOVERY;
    };

    static VOID CALLBACK DnsResolveCompletion(
        DWORD error, DWORD, LPOVERLAPPED overlapped) {
        auto* context = reinterpret_cast<DnsResolveContext*>(overlapped);
        context->completionError = error;
        SetEvent(context->completionEvent);
    }

    static bool ResolveServerAddresses(
        const std::string& serverName, int serverPort,
        ADDRINFOEXW** addresses, DWORD timeoutMs) {
        if (!addresses || serverName.empty() || serverPort <= 0 || serverPort > 65535) {
            return false;
        }
        *addresses = nullptr;

        // Preserve the existing ANSI hostname interpretation used by getaddrinfo().
        const int hostLength = MultiByteToWideChar(
            CP_ACP, 0, serverName.c_str(), -1, nullptr, 0);
        if (hostLength <= 0) {
            return false;
        }

        std::wstring wideHost(static_cast<size_t>(hostLength), L'\0');
        if (MultiByteToWideChar(
                CP_ACP, 0, serverName.c_str(), -1, wideHost.data(), hostLength) == 0) {
            return false;
        }

        const std::wstring wideService = std::to_wstring(serverPort);
        ADDRINFOEXW hints{};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        DnsResolveContext context{};
        context.completionEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!context.completionEvent) {
            return false;
        }

        HANDLE cancelHandle = nullptr;
        const INT startResult = GetAddrInfoExW(
            wideHost.c_str(), wideService.c_str(), NS_ALL, nullptr, &hints,
            &context.results, nullptr, &context.overlapped,
            DnsResolveCompletion, &cancelHandle);

        DWORD resolveError = static_cast<DWORD>(startResult);
        if (startResult == WSA_IO_PENDING) {
            const DWORD waitResult = WaitForSingleObject(
                context.completionEvent, timeoutMs);
            if (waitResult != WAIT_OBJECT_0) {
                // Cancellation invokes the completion callback. Wait for it before
                // releasing the OVERLAPPED context or calling WSACleanup.
                if (cancelHandle) {
                    GetAddrInfoExCancel(&cancelHandle);
                }
                WaitForSingleObject(context.completionEvent, INFINITE);
            }
            resolveError = context.completionError;
        }

        const bool succeeded = resolveError == NO_ERROR && context.results != nullptr;
        if (succeeded) {
            *addresses = context.results;
            context.results = nullptr;
        }

        if (context.results) {
            FreeAddrInfoExW(context.results);
        }
        CloseHandle(context.completionEvent);
        return succeeded;
    }

    static bool ReceiveFrame(SOCKET socket, std::string& pending,
                             std::string& frame, DWORD timeoutMs,
                             size_t maxSize = 4096) {
        const auto deadline = std::chrono::steady_clock::now() +
                              std::chrono::milliseconds(timeoutMs);
        for (;;) {
            const size_t delimiter = pending.find(';');
            if (delimiter != std::string::npos) {
                if (delimiter + 1 > maxSize) return false;
                frame.assign(pending, 0, delimiter + 1);
                pending.erase(0, delimiter + 1);
                return true;
            }
            if (pending.size() >= maxSize) return false;
            const auto now = std::chrono::steady_clock::now();
            if (now >= deadline) return false;
            const auto us = std::chrono::duration_cast<std::chrono::microseconds>(deadline - now).count();
            timeval tv{};
            tv.tv_sec = static_cast<long>(us / 1000000);
            tv.tv_usec = static_cast<long>(us % 1000000);
            fd_set readSet;
            FD_ZERO(&readSet);
            FD_SET(socket, &readSet);
            if (select(0, &readSet, nullptr, nullptr, &tv) <= 0) return false;
            char buffer[512];
            const int received = recv(socket, buffer, sizeof(buffer), 0);
            if (received <= 0) return false;
            pending.append(buffer, static_cast<size_t>(received));
            if (pending.size() > maxSize && pending.find(';') == std::string::npos) return false;
        }
    }

    NetworkReporter::NetworkReporter(const std::string& serverIP, int serverPort, const std::string& secretKey)
        : m_serverIP(serverIP), m_serverPort(serverPort), m_secretKey(secretKey), m_hbSocket(INVALID_SOCKET) {
        if (m_secretKey.empty()) throw std::invalid_argument("Client secret is not configured");
        // Inisialisasi Winsock sekali saja untuk seluruh aplikasi
        // Catatan: WSAStartup bisa dipanggil beberapa kali, setiap panggilan harus diikuti WSACleanup
        WSADATA wsaData;
        int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
        if (iResult != 0) throw std::runtime_error("WSAStartup failed");
        m_winsockInitialized = true;
        
        // --- GENERATE HWID SAAT PEMBUATAN OBJEK ---
        // Gunakan try-catch untuk menangani error dari WMI atau hashing
        try {
            m_hwid = HWIDGenerator::Generate();
            // Jika Generate() mengembalikan string kosong, gunakan fallback
            if (m_hwid.empty()) {
                m_hwid = "UNKNOWN";
            }
        } catch (...) {
            // Jika ada exception (misalnya dari WMI), gunakan fallback
            m_hwid = "UNKNOWN";
        }
    }

    NetworkReporter::~NetworkReporter() {
        // Stop heartbeat dan cleanup socket
        StopHeartbeat();
        if (m_hbSocket != INVALID_SOCKET) {
            closesocket(m_hbSocket);
            m_hbSocket = INVALID_SOCKET;
        }
        if (m_winsockInitialized) {
            WSACleanup();
            m_winsockInitialized = false;
        }
    }

    bool NetworkReporter::CheckBanStatus() {
        // Fungsi untuk check-in ke server dan mengecek apakah HWID di-ban
        SOCKET connectSocket = INVALID_SOCKET;
        ADDRINFOEXW* result = nullptr;
        ADDRINFOEXW* ptr = nullptr;

        // DNS resolution is cancellable and bounded before the TCP connect deadline.
        if (!ResolveServerAddresses(m_serverIP, m_serverPort, &result, 5000)) {
            // Gagal resolve alamat server - Fail-Closed
            MessageBoxW(NULL, L"Gagal menyelesaikan alamat server.\n\nClient akan ditutup.", L"Oblivion Hack Shield - Error", MB_OK | MB_ICONERROR | MB_TOPMOST);
            ExitProcess(1);
        }

        // Share one deadline across all resolved addresses.
        const auto connectDeadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        // Attempt to connect to an address until one succeeds or the deadline expires.
        for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {
            if (std::chrono::steady_clock::now() >= connectDeadline) {
                break;
            }
            connectSocket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
            if (connectSocket == INVALID_SOCKET) {
                continue;
            }

            // Connect without allowing an unreachable endpoint to block indefinitely.
            if (!ConnectWithDeadline(connectSocket, ptr->ai_addr,
                                     static_cast<int>(ptr->ai_addrlen), connectDeadline)) {
                closesocket(connectSocket);
                connectSocket = INVALID_SOCKET;
                continue;
            }
            break; // Connected
        }

        FreeAddrInfoExW(result);

        if (connectSocket == INVALID_SOCKET) {
            // Gagal terhubung - Fail-Closed
            MessageBoxW(NULL, L"Tidak dapat terhubung ke server keamanan.\n\nClient akan ditutup.", L"Oblivion Hack Shield - Error", MB_OK | MB_ICONERROR | MB_TOPMOST);
            ExitProcess(0);
        }

        std::string challengeNonce;
        if (!BeginAuthenticatedRequest(
                connectSocket, m_hwid, m_secretKey, m_pendingNetworkData, challengeNonce)) {
            closesocket(connectSocket);
            MessageBoxW(NULL, L"Autentikasi challenge server tidak valid.",
                        L"Oblivion Hack Shield - Error", MB_OK | MB_ICONERROR | MB_TOPMOST);
            ExitProcess(1);
            return false;
        }

        const std::string checkinDetails;
        const std::string checkinMac = HmacSha256(
            m_secretKey, BuildRequestAuthData("CHECKIN", checkinDetails, m_hwid, challengeNonce));
        if (checkinMac.size() != 64) {
            closesocket(connectSocket);
            ExitProcess(1);
            return false;
        }
        const std::string checkin =
            "CHECKIN::" + m_hwid + ":" + challengeNonce + ":" + checkinMac + ";";
        if (!SendAll(connectSocket, checkin)) {
            closesocket(connectSocket);
            ExitProcess(1);
            return false;
        }

        std::string statusFrame;
        if (!ReceiveFrame(connectSocket, m_pendingNetworkData, statusFrame, 3000, 512)) {
            closesocket(connectSocket);
            MessageBoxW(NULL, L"Respons autentikasi server tidak lengkap.", L"Oblivion Hack Shield - Error",
                        MB_OK | MB_ICONERROR | MB_TOPMOST);
            ExitProcess(1);
            return false;
        }

        if (VerifyControlFrame(statusFrame, "KICK", m_secretKey, m_hwid, challengeNonce)) {
            closesocket(connectSocket);
            MessageBoxW(NULL, L"HWID Anda telah di-ban dari server.", L"Oblivion Hack Shield - Banned",
                        MB_OK | MB_ICONERROR | MB_TOPMOST);
            ExitProcess(0);
            return false;
        }
        if (!VerifyControlFrame(statusFrame, "OK", m_secretKey, m_hwid, challengeNonce)) {
            closesocket(connectSocket);
            MessageBoxW(NULL, L"Respons autentikasi server tidak valid.", L"Oblivion Hack Shield - Error",
                        MB_OK | MB_ICONERROR | MB_TOPMOST);
            ExitProcess(1);
            return false;
        }

        std::string nonceFrame;
        const std::string noncePrefix = "SESSION_NONCE:";
        if (!ReceiveFrame(connectSocket, m_pendingNetworkData, nonceFrame, 3000, 128) ||
            nonceFrame.rfind(noncePrefix, 0) != 0 || nonceFrame.back() != ';') {
            closesocket(connectSocket);
            MessageBoxW(NULL, L"Nonce sesi dari server tidak valid.", L"Oblivion Hack Shield - Error",
                        MB_OK | MB_ICONERROR | MB_TOPMOST);
            ExitProcess(1);
            return false;
        }

        const std::string nonceText = nonceFrame.substr(
            noncePrefix.size(), nonceFrame.size() - noncePrefix.size() - 1);
        // Server sends its active heartbeat interval/timeout as a separate frame.
        if (nonceText.empty() || nonceText.size() > 20 ||
            !std::all_of(nonceText.begin(), nonceText.end(),
                [](unsigned char c) { return c >= '0' && c <= '9'; })) {
            closesocket(connectSocket);
            ExitProcess(1);
            return false;
        }
        try {
            size_t parsed = 0;
            const auto nonce = std::stoull(nonceText, &parsed, 10);
            if (parsed != nonceText.size()) throw std::invalid_argument("invalid nonce");
            m_sessionNonce = static_cast<uint64_t>(nonce);
        } catch (...) {
            closesocket(connectSocket);
            ExitProcess(1);
            return false;
        }

        // Server sends its active heartbeat interval/timeout as a separate frame.
        std::string configFrame;
        if (!ReceiveFrame(connectSocket, m_pendingNetworkData, configFrame, 3000, 128) ||
            configFrame.rfind("HB_CONFIG:", 0) != 0 || configFrame.back() != ';') {
            closesocket(connectSocket);
            MessageBoxW(NULL, L"Konfigurasi heartbeat dari server tidak valid.",
                        L"Oblivion Hack Shield - Error", MB_OK | MB_ICONERROR | MB_TOPMOST);
            ExitProcess(1);
            return false;
        }

        const std::string configPayload = configFrame.substr(
            strlen("HB_CONFIG:"), configFrame.size() - strlen("HB_CONFIG:") - 1);
        const size_t separator = configPayload.find(':');
        if (separator == std::string::npos ||
            configPayload.find(':', separator + 1) != std::string::npos) {
            closesocket(connectSocket);
            ExitProcess(1);
            return false;
        }

        std::string intervalText = configPayload.substr(0, separator);
        std::string timeoutText = configPayload.substr(separator + 1);
        try {
            size_t parsedInterval = 0, parsedTimeout = 0;
            const unsigned long long interval = std::stoull(intervalText, &parsedInterval, 10);
            const unsigned long long timeout = std::stoull(timeoutText, &parsedTimeout, 10);
            if (parsedInterval != intervalText.size() || parsedTimeout != timeoutText.size() ||
                interval < 100 || interval > 60000 || timeout < 250 || timeout > 120000) {
                throw std::invalid_argument("heartbeat config out of range");
            }
            m_hbIntervalMs = static_cast<uint32_t>(interval);
            m_hbTimeoutMs = static_cast<uint32_t>(timeout);
        } catch (...) {
            closesocket(connectSocket);
            MessageBoxW(NULL, L"Nilai konfigurasi heartbeat tidak valid.",
                        L"Oblivion Hack Shield - Error", MB_OK | MB_ICONERROR | MB_TOPMOST);
            ExitProcess(1);
            return false;
        }

        std::string sessionAuthFrame;
        const std::string sessionAuthPrefix = "SESSION_AUTH:";
        if (!ReceiveFrame(connectSocket, m_pendingNetworkData, sessionAuthFrame, 3000, 128) ||
            sessionAuthFrame.rfind(sessionAuthPrefix, 0) != 0 ||
            sessionAuthFrame.back() != ';') {
            closesocket(connectSocket);
            MessageBoxW(NULL, L"Autentikasi respons sesi server tidak valid.",
                        L"Oblivion Hack Shield - Error", MB_OK | MB_ICONERROR | MB_TOPMOST);
            ExitProcess(1);
            return false;
        }

        const std::string sessionServerMac = sessionAuthFrame.substr(
            sessionAuthPrefix.size(), sessionAuthFrame.size() - sessionAuthPrefix.size() - 1);
        const std::string expectedSessionMac = HmacSha256(
            m_secretKey, "SESSION:" + m_hwid + ":" + challengeNonce + ":" +
            nonceText + ":" + intervalText + ":" + timeoutText);
        if (!ConstantTimeEquals(expectedSessionMac, sessionServerMac)) {
            closesocket(connectSocket);
            MessageBoxW(NULL, L"Autentikasi konfigurasi sesi gagal.",
                        L"Oblivion Hack Shield - Error", MB_OK | MB_ICONERROR | MB_TOPMOST);
            ExitProcess(1);
            return false;
        }

        m_hbSocket = connectSocket;
        StartHeartbeat();
        return true;
    }

    // --- HEARTBEAT IMPLEMENTATION (basic ping/pong) ---
    // Secure HMAC-SHA256 via Windows CNG (bcrypt)
    static std::string HmacSha256(const std::string& key, const std::string& data) {
        BCRYPT_ALG_HANDLE hAlg = NULL;
        BCRYPT_HASH_HANDLE hHash = NULL;
        NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC);
        if (status != 0) return std::string();
        DWORD objLen = 0, dataLen = 0;
        status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objLen, sizeof(DWORD), &dataLen, 0);
        if (status != 0 || objLen == 0) {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return std::string();
        }
        std::vector<UCHAR> obj(objLen);
        status = BCryptCreateHash(hAlg, &hHash, obj.data(), objLen, (PUCHAR)key.data(), (ULONG)key.size(), 0);
        if (status != 0) { BCryptCloseAlgorithmProvider(hAlg,0); return std::string(); }
        status = BCryptHashData(hHash, (PUCHAR)data.data(), (ULONG)data.size(), 0);
        if (status != 0) { BCryptDestroyHash(hHash); BCryptCloseAlgorithmProvider(hAlg,0); return std::string(); }
        UCHAR hash[32];
        status = BCryptFinishHash(hHash, hash, sizeof(hash), 0);
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        if (status != 0) return std::string();
        static const char* hex = "0123456789abcdef";
        std::string out; out.reserve(64);
        for (int i = 0; i < 32; ++i) { out.push_back(hex[(hash[i]>>4)&0xF]); out.push_back(hex[hash[i]&0xF]); }
        return out;
    }

    void NetworkReporter::StartHeartbeat() {
        // Production heartbeat cannot be disabled by a client-controlled environment variable.
        if (m_hbRunning.load() || m_hbSocket == INVALID_SOCKET) return;
        m_hbRunning.store(true);
        try {
            m_hbThread = std::thread([this]() {
                const SOCKET socket = m_hbSocket;
                const std::string sessionKey =
                    HmacSha256(m_secretKey, m_hwid + ":" + std::to_string(m_sessionNonce));
                if (sessionKey.empty()) {
                    m_hbRunning.store(false);
                    ReportViolationAndExit(L"", "HEARTBEAT_CRYPTO_FAILURE",
                                           "Unable to derive heartbeat session key");
                    return;
                }

                Oblivion::HeartbeatConfig cfg;
                cfg.interval_ms = m_hbIntervalMs;
                cfg.timeout_ms = m_hbTimeoutMs;
                while (m_hbRunning.load()) {
                    std::string frame;
                    if (!ReceiveFrame(socket, m_pendingNetworkData, frame,
                                      cfg.timeout_ms + cfg.interval_ms, 512)) break;
                    if (frame.rfind("PING:", 0) != 0 || frame.back() != ';') break;
                    const std::string payload = frame.substr(0, frame.size() - 1);
                    const size_t p1 = payload.find(':');
                    const size_t p2 = payload.find(':', p1 == std::string::npos ? p1 : p1 + 1);
                    const size_t p3 = payload.find(':', p2 == std::string::npos ? p2 : p2 + 1);
                    const size_t p4 = payload.find(':', p3 == std::string::npos ? p3 : p3 + 1);
                    if (p1 == std::string::npos || p2 == std::string::npos ||
                        p3 == std::string::npos || p4 == std::string::npos ||
                        payload.find(':', p4 + 1) != std::string::npos) break;
                    try {
                        const std::string seqText = payload.substr(p1 + 1, p2 - p1 - 1);
                        const std::string timestampText = payload.substr(p2 + 1, p3 - p2 - 1);
                        const std::string nonceText = payload.substr(p3 + 1, p4 - p3 - 1);
                        const std::string receivedMac = payload.substr(p4 + 1);
                        size_t parsedSeq = 0, parsedTimestamp = 0, parsedNonce = 0;
                        const unsigned long long seq64 = std::stoull(seqText, &parsedSeq, 10);
                        const unsigned long long timestamp = std::stoull(timestampText, &parsedTimestamp, 10);
                        const unsigned long long nonce = std::stoull(nonceText, &parsedNonce, 10);
                        if (parsedSeq != seqText.size() || parsedTimestamp != timestampText.size() ||
                            parsedNonce != nonceText.size() ||
                            seq64 > (std::numeric_limits<uint32_t>::max)()) break;

                        const uint32_t seq = static_cast<uint32_t>(seq64);
                        const std::string pingAuthData =
                            "PING:" + seqText + ":" + timestampText + ":" + nonceText + ":" + m_hwid;
                        const std::string expectedPingMac = HmacSha256(sessionKey, pingAuthData);
                        if (!ConstantTimeEquals(expectedPingMac, receivedMac)) break;

                        const std::string pongData = std::to_string(seq) + ":" + timestampText +
                                                     ":" + nonceText + ":" + m_hwid;
                        const std::string mac = HmacSha256(sessionKey, pongData);
                        if (mac.size() != 64) break;
                        const std::string pong = "PONG:" + std::to_string(seq) + ":" +
                            std::to_string(static_cast<uint64_t>(GetTickCount64())) + ":" +
                            std::to_string(nonce) + ":1|1:" + m_hwid + ":" + mac + ";";
                        if (!SendAll(socket, pong)) break;
                    } catch (...) { break; }
                }
                const bool endedUnexpectedly = m_hbRunning.load();
                m_hbRunning.store(false);
                if (endedUnexpectedly) {
                    ReportViolationAndExit(L"", "HEARTBEAT_CONNECTION_LOST",
                                           "Heartbeat stream ended or contained an invalid frame");
                }
            });
        } catch (...) {
            m_hbRunning.store(false);
            throw;
        }
    }

    void NetworkReporter::StopHeartbeat() {
        m_hbRunning.store(false);
        if (m_hbSocket != INVALID_SOCKET) shutdown(m_hbSocket, SD_BOTH);
        if (m_hbThread.joinable() && m_hbThread.get_id() != std::this_thread::get_id())
            m_hbThread.join();
    }

    void NetworkReporter::ReportViolation(const std::string& type, const std::string& details) {
        // BLOCKING: Menunggu respons dari server sebelum kembali
        // Ini diperlukan agar client menunggu respons KICK dari server
        SOCKET connectSocket = INVALID_SOCKET;
        ADDRINFOEXW* result = nullptr;
        ADDRINFOEXW* ptr = nullptr;

        // DNS resolution is cancellable and bounded before the TCP connect deadline.
        if (!ResolveServerAddresses(m_serverIP, m_serverPort, &result, 5000)) {
            // Gagal resolve alamat server - Fail-Closed
            MessageBoxW(NULL, L"Gagal menyelesaikan alamat server.\n\nClient akan ditutup.", L"Oblivion Hack Shield - Error", MB_OK | MB_ICONERROR | MB_TOPMOST);
            ExitProcess(1);
        }

        // Share one deadline across all resolved addresses.
        const auto connectDeadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        // Attempt to connect to an address until one succeeds or the deadline expires.
        for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {
            if (std::chrono::steady_clock::now() >= connectDeadline) {
                break;
            }
            connectSocket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
            if (connectSocket == INVALID_SOCKET) {
                continue;
            }

            // Connect without allowing an unreachable endpoint to block indefinitely.
            if (!ConnectWithDeadline(connectSocket, ptr->ai_addr,
                                     static_cast<int>(ptr->ai_addrlen), connectDeadline)) {
                closesocket(connectSocket);
                connectSocket = INVALID_SOCKET;
                continue;
            }
            break; // Connected
        }

        FreeAddrInfoExW(result);

        if (connectSocket == INVALID_SOCKET) {
            // --- GAGAL TERHUBUNG ---
            // Kebijakan "Fail-Closed": Jika tidak bisa hubungi server, anggap sebagai pelanggaran.
            MessageBoxW(NULL, L"Tidak dapat terhubung ke server keamanan.\n\nClient akan ditutup.", L"Oblivion Hack Shield - Error", MB_OK | MB_ICONERROR | MB_TOPMOST);
            ExitProcess(0);
            return;
        }

        // --- FORMAT LAPORAN BARU MENGGUNAKAN HWID ---
        // Sanitasi details: replace colon dengan pipe untuk menghindari konflik parsing
        std::string sanitizedDetails = details;
        for (char& c : sanitizedDetails) {
            if (c == ':') c = '|';  // Replace colon dengan pipe
            if (c == ';') c = ',';  // Replace semicolon dengan comma (delimiter utama)
        }
        
        std::string responsePending;
        std::string challengeNonce;
        if (!BeginAuthenticatedRequest(
                connectSocket, m_hwid, m_secretKey, responsePending, challengeNonce)) {
            closesocket(connectSocket);
            MessageBoxW(NULL, L"Autentikasi challenge server tidak valid.",
                        L"Oblivion Hack Shield - Error", MB_OK | MB_ICONERROR | MB_TOPMOST);
            ExitProcess(1);
            return;
        }

        const std::string reportMac = HmacSha256(
            m_secretKey, BuildRequestAuthData(type, sanitizedDetails, m_hwid, challengeNonce));
        if (reportMac.size() != 64) {
            closesocket(connectSocket);
            ExitProcess(1);
            return;
        }
        const std::string report =
            type + ":" + sanitizedDetails + ":" + m_hwid + ":" + challengeNonce + ":" +
            reportMac + ";";
        if (!SendAll(connectSocket, report)) {
            // Gagal mengirim laporan - Fail-Closed
            closesocket(connectSocket);
            MessageBoxW(NULL, L"Gagal mengirim laporan ke server.\n\nClient akan ditutup.", L"Oblivion Hack Shield - Error", MB_OK | MB_ICONERROR | MB_TOPMOST);
            ExitProcess(1);
        }

        // The server acknowledges every report with exactly one framed response.
        std::string responseFrame;
        if (!ReceiveFrame(connectSocket, responsePending, responseFrame, 3000, 512)) {
            closesocket(connectSocket);
            MessageBoxW(NULL, L"Timeout atau respons server tidak lengkap saat mengirim laporan.",
                        L"Oblivion Hack Shield - Error", MB_OK | MB_ICONERROR | MB_TOPMOST);
            ExitProcess(0);
            return;
        }

        if (VerifyControlFrame(responseFrame, "KICK", m_secretKey, m_hwid, challengeNonce)) {
            closesocket(connectSocket);
            MessageBoxW(NULL, L"Server mendeteksi pelanggaran.\n\nClient akan ditutup.",
                        L"Oblivion Hack Shield - Violation", MB_OK | MB_ICONERROR | MB_TOPMOST);
            ExitProcess(0);
            return;
        }
        if (!VerifyControlFrame(responseFrame, "OK", m_secretKey, m_hwid, challengeNonce)) {
            closesocket(connectSocket);
            MessageBoxW(NULL, L"Respons server tidak valid saat mengirim laporan.",
                        L"Oblivion Hack Shield - Error", MB_OK | MB_ICONERROR | MB_TOPMOST);
            ExitProcess(0);
            return;
        }

        closesocket(connectSocket);
    }
}