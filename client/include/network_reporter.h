#pragma once

#include <atomic>
#include <cstdint>
#include <string>
#include <thread>
#include <winsock2.h>

namespace Oblivion {
    class NetworkReporter {
    public:
        NetworkReporter(const std::string& serverIP, int serverPort, const std::string& secretKey);
        ~NetworkReporter();

        // Fungsi untuk check-in ke server (cek apakah di-ban)
        // Mengembalikan true jika diizinkan, false jika di-ban
        bool CheckBanStatus();

        // Fungsi utama untuk melaporkan pelanggaran
        void ReportViolation(const std::string& type, const std::string& details);

        // Heartbeat: start and stop (future use)
        void StartHeartbeat();
        void StopHeartbeat();

    private:
        std::string m_serverIP;
        int m_serverPort;
        std::string m_hwid;  // Hardware ID yang di-generate saat konstruktor
        std::string m_secretKey; // Secret sederhana untuk autentikasi dasar

        // Internal heartbeat state
        std::atomic<bool> m_hbRunning{ false };
        std::thread m_hbThread;
        std::string m_pendingNetworkData; // Buffer untuk byte TCP yang belum membentuk frame
        SOCKET m_hbSocket = INVALID_SOCKET; // Socket untuk heartbeat
        uint64_t m_sessionNonce = 0; // Session nonce dari server
        uint32_t m_hbIntervalMs = 3000;
        uint32_t m_hbTimeoutMs = 4000;
        bool m_winsockInitialized = false;
    };
}