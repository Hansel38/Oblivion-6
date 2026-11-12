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
        struct addrinfo* result = NULL, * ptr = NULL, hints;

        ZeroMemory(&hints, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        // Resolve server address and port
        std::string portStr = std::to_string(m_serverPort);
        int iResult = getaddrinfo(m_serverIP.c_str(), portStr.c_str(), &hints, &result);
        if (iResult != 0) {
            // Gagal resolve alamat server - Fail-Closed
            MessageBoxW(NULL, L"Gagal menyelesaikan alamat server.\n\nClient akan ditutup.", L"Oblivion Hack Shield - Error", MB_OK | MB_ICONERROR | MB_TOPMOST);
            ExitProcess(1);
        }

        // Attempt to connect to an address until one succeeds
        for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {
            connectSocket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
            if (connectSocket == INVALID_SOCKET) {
                continue;
            }

            // Connect to server.
            if (connect(connectSocket, ptr->ai_addr, (int)ptr->ai_addrlen) == SOCKET_ERROR) {
                closesocket(connectSocket);
                connectSocket = INVALID_SOCKET;
                continue;
            }
            break; // Connected
        }

        freeaddrinfo(result);

        if (connectSocket == INVALID_SOCKET) {
            // Gagal terhubung - Fail-Closed
            MessageBoxW(NULL, L"Tidak dapat terhubung ke server keamanan.\n\nClient akan ditutup.", L"Oblivion Hack Shield - Error", MB_OK | MB_ICONERROR | MB_TOPMOST);
            ExitProcess(0);
        }

        const std::string checkin = "CHECKIN::" + m_hwid + ":" + m_secretKey + ";";
        if (!SendAll(connectSocket, checkin)) {
            closesocket(connectSocket);
            ExitProcess(1);
            return false;
        }

        std::string response;
        if (!ReceiveFrame(connectSocket, m_pendingNetworkData, response, 3000, 512)) {
            closesocket(connectSocket);
            MessageBoxW(NULL, L"Respons autentikasi server tidak lengkap.", L"Oblivion Hack Shield - Error",
                        MB_OK | MB_ICONERROR | MB_TOPMOST);
            ExitProcess(1);
            return false;
        }
        // Server sends "OK;" followed by "SESSION_NONCE:...;" on the same TCP stream.
        if (response == "OK;") {
            std::string nonceFrame;
            if (!ReceiveFrame(connectSocket, m_pendingNetworkData, nonceFrame, 3000, 512)) {
                closesocket(connectSocket);
                ExitProcess(1);
                return false;
            }
            response += nonceFrame;
        }

        if (response == "KICK;") {
            closesocket(connectSocket);
            MessageBoxW(NULL, L"HWID Anda telah di-ban dari server.", L"Oblivion Hack Shield - Banned",
                        MB_OK | MB_ICONERROR | MB_TOPMOST);
            ExitProcess(0);
            return false;
        }

        const std::string noncePrefix = "OK;SESSION_NONCE:";
        if (response.rfind(noncePrefix, 0) != 0 || response.back() != ';') {
            closesocket(connectSocket);
            MessageBoxW(NULL, L"Respons autentikasi server tidak valid.", L"Oblivion Hack Shield - Error",
                        MB_OK | MB_ICONERROR | MB_TOPMOST);
            ExitProcess(1);
            return false;
        }
        const std::string nonceText = response.substr(noncePrefix.size(),
                                                       response.size() - noncePrefix.size() - 1);
        if (nonceText.empty() || !std::all_of(nonceText.begin(), nonceText.end(),
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

        try {
            const std::string intervalText = configPayload.substr(0, separator);
            const std::string timeoutText = configPayload.substr(separator + 1);
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
                    if (p1 == std::string::npos || p2 == std::string::npos ||
                        p3 == std::string::npos || payload.find(':', p3 + 1) != std::string::npos) break;
                    try {
                        const auto seq64 = std::stoull(payload.substr(p1 + 1, p2 - p1 - 1));
                        if (seq64 > (std::numeric_limits<uint32_t>::max)()) break;
                        const uint32_t seq = static_cast<uint32_t>(seq64);
                        const uint64_t ts = std::stoull(payload.substr(p2 + 1, p3 - p2 - 1));
                        const uint64_t nonce = std::stoull(payload.substr(p3 + 1));
                        const std::string data = std::to_string(seq) + ":" + std::to_string(ts) +
                                                 ":" + std::to_string(nonce) + ":" + m_hwid;
                        const std::string mac = HmacSha256(sessionKey, data);
                        if (mac.empty()) break;
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
        struct addrinfo* result = NULL, * ptr = NULL, hints;

        ZeroMemory(&hints, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        // Resolve server address and port
        std::string portStr = std::to_string(m_serverPort);
        int iResult = getaddrinfo(m_serverIP.c_str(), portStr.c_str(), &hints, &result);
        if (iResult != 0) {
            // Gagal resolve alamat server - Fail-Closed
            MessageBoxW(NULL, L"Gagal menyelesaikan alamat server.\n\nClient akan ditutup.", L"Oblivion Hack Shield - Error", MB_OK | MB_ICONERROR | MB_TOPMOST);
            ExitProcess(1);
        }

        // Attempt to connect to an address until one succeeds
        for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {
            connectSocket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
            if (connectSocket == INVALID_SOCKET) {
                continue;
            }

            // Connect to server.
            if (connect(connectSocket, ptr->ai_addr, (int)ptr->ai_addrlen) == SOCKET_ERROR) {
                closesocket(connectSocket);
                connectSocket = INVALID_SOCKET;
                continue;
            }
            break; // Connected
        }

        freeaddrinfo(result);

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
        
        std::string report = type + ":" + sanitizedDetails + ":" + m_hwid + ":" + m_secretKey + ";";
        if (!SendAll(connectSocket, report)) {
            // Gagal mengirim laporan - Fail-Closed
            closesocket(connectSocket);
            MessageBoxW(NULL, L"Gagal mengirim laporan ke server.\n\nClient akan ditutup.", L"Oblivion Hack Shield - Error", MB_OK | MB_ICONERROR | MB_TOPMOST);
            ExitProcess(1);
        }

        // The server acknowledges every report with exactly one framed response.
        std::string responsePending;
        std::string responseFrame;
        if (!ReceiveFrame(connectSocket, responsePending, responseFrame, 3000, 512)) {
            closesocket(connectSocket);
            MessageBoxW(NULL, L"Timeout atau respons server tidak lengkap saat mengirim laporan.",
                        L"Oblivion Hack Shield - Error", MB_OK | MB_ICONERROR | MB_TOPMOST);
            ExitProcess(0);
            return;
        }

        if (responseFrame == "KICK;") {
            closesocket(connectSocket);
            MessageBoxW(NULL, L"Server mendeteksi pelanggaran.\n\nClient akan ditutup.",
                        L"Oblivion Hack Shield - Violation", MB_OK | MB_ICONERROR | MB_TOPMOST);
            ExitProcess(0);
            return;
        }
        if (responseFrame != "OK;") {
            closesocket(connectSocket);
            MessageBoxW(NULL, L"Respons server tidak valid saat mengirim laporan.",
                        L"Oblivion Hack Shield - Error", MB_OK | MB_ICONERROR | MB_TOPMOST);
            ExitProcess(0);
            return;
        }

        closesocket(connectSocket);
    }
}