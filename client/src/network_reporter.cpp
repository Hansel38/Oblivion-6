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
#include <bcrypt.h>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Bcrypt.lib")

#ifndef BCRYPT_ALG_HANDLE_HMAC
#define BCRYPT_ALG_HANDLE_HMAC 0x00000008
#endif

namespace Oblivion {
    NetworkReporter::NetworkReporter(const std::string& serverIP, int serverPort, const std::string& secretKey)
        : m_serverIP(serverIP), m_serverPort(serverPort), m_secretKey(secretKey), m_hbSocket(INVALID_SOCKET) {
        // Inisialisasi Winsock sekali saja untuk seluruh aplikasi
        // Catatan: WSAStartup bisa dipanggil beberapa kali, setiap panggilan harus diikuti WSACleanup
        WSADATA wsaData;
        int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
        // Jika WSAStartup gagal, gunakan fallback (jangan tutup aplikasi di constructor)
        if (iResult != 0) {
            m_hwid = "UNKNOWN";
            return;
        }
        
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
        // Cleanup Winsock saat DLL dibongkar
        WSACleanup();
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

        // Kirim check-in dengan secret: "CHECKIN::HWID:SECRET;"
        std::string checkin = "CHECKIN::" + m_hwid + ":" + m_secretKey + ";";
        int bytesSent = send(connectSocket, checkin.c_str(), (int)checkin.length(), 0);
        if (bytesSent == SOCKET_ERROR || bytesSent == 0) {
            closesocket(connectSocket);
            MessageBoxW(NULL, L"Gagal mengirim check-in ke server.\n\nClient akan ditutup.", L"Oblivion Hack Shield - Error", MB_OK | MB_ICONERROR | MB_TOPMOST);
            ExitProcess(1);
        }

        // Tunggu respons dari server dengan timeout
        char recvbuf[512] = { 0 };
        int recvbuflen = 512;
        fd_set fdset;
        struct timeval tv;
        tv.tv_sec = 3; // Timeout 3 detik
        tv.tv_usec = 0;
        FD_ZERO(&fdset);
        FD_SET(connectSocket, &fdset);

        int selectResult = select(0, &fdset, NULL, NULL, &tv);
        bool isBanned = false;
        if (selectResult > 0) {
            int bytesReceived = recv(connectSocket, recvbuf, recvbuflen, 0);
            if (bytesReceived > 0) {
                // Parse response - lebih robust
                std::string response(recvbuf, bytesReceived);
                
                // Hapus semua null terminator dan whitespace
                response.erase(std::remove(response.begin(), response.end(), '\0'), response.end());
                
                // Trim whitespace dari awal dan akhir
                size_t start = response.find_first_not_of(" \t\n\r");
                if (start != std::string::npos) {
                    response = response.substr(start);
                }
                size_t end = response.find_last_not_of(" \t\n\r");
                if (end != std::string::npos) {
                    response = response.substr(0, end + 1);
                }
                
                // Cek apakah response mengandung "KICK" (case-insensitive untuk lebih aman)
                std::string responseUpper = response;
                std::transform(responseUpper.begin(), responseUpper.end(), responseUpper.begin(), ::toupper);
                
                if (responseUpper.find("KICK") != std::string::npos || response == "KICK;") {
                    isBanned = true;
                } else if (responseUpper.find("OK") != std::string::npos) {
                    // OK received - simpan socket untuk heartbeat
                    m_hbSocket = connectSocket;
                    m_sessionNonce = 0;
                    
                    // Parse SESSION_NONCE jika ada
                    size_t posSN = response.find("SESSION_NONCE:");
                    if (posSN != std::string::npos) {
                        size_t end = response.find(';', posSN);
                        std::string sn = response.substr(posSN + strlen("SESSION_NONCE:"), end==std::string::npos?std::string::npos:end - (posSN + strlen("SESSION_NONCE:")));
                        try { m_sessionNonce = std::stoull(sn); } catch (...) { m_sessionNonce = 0; }
                    }
                    
                    // Start heartbeat loop di thread terpisah dengan socket yang sama
                    StartHeartbeat();
                    return true; // Jangan close socket, akan digunakan untuk heartbeat
                }
            }
        } else {
            // Timeout - Fail-Closed
            closesocket(connectSocket);
            MessageBoxW(NULL, L"Timeout menunggu respons server.\n\nClient akan ditutup.", L"Oblivion Hack Shield - Error", MB_OK | MB_ICONERROR | MB_TOPMOST);
            // Paksa tutup segera
            Sleep(100); // Beri waktu untuk MessageBox ditutup
            ExitProcess(0);
            TerminateProcess(GetCurrentProcess(), 0);
            return false;
        }

        closesocket(connectSocket);
        
        if (isBanned) {
            // HWID di-ban, tampilkan pesan dan tutup
            MessageBoxW(NULL, L"HWID Anda telah di-ban dari server.\n\nClient akan ditutup.", L"Oblivion Hack Shield - Banned", MB_OK | MB_ICONERROR | MB_TOPMOST);
            
            // Beri waktu singkat untuk MessageBox ditutup, lalu paksa tutup proses
            Sleep(100);
            
            // Paksa tutup proses dengan beberapa metode untuk memastikan
            ExitProcess(0);
            
            // Fallback jika ExitProcess tidak bekerja
            TerminateProcess(GetCurrentProcess(), 0);
            
            // Tidak akan sampai di sini
            return false;
        }
        
        return true; // Tidak di-ban, boleh lanjut
    }

    // --- HEARTBEAT IMPLEMENTATION (basic ping/pong) ---
    // Secure HMAC-SHA256 via Windows CNG (bcrypt)
    static std::string HmacSha256(const std::string& key, const std::string& data) {
        BCRYPT_ALG_HANDLE hAlg = NULL;
        BCRYPT_HASH_HANDLE hHash = NULL;
        NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC);
        if (status != 0) return std::string();
        DWORD objLen = 0, dataLen = 0;
        (void)BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objLen, sizeof(DWORD), &dataLen, 0);
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
        // Allow disabling via environment
        char envVal[32] = {0};
        DWORD n = GetEnvironmentVariableA("OBLV_HB_DISABLE", envVal, sizeof(envVal));
        if (n > 0) {
            return; // heartbeat disabled via env
        }
        if (m_hbRunning) return;
        if (m_hbSocket == INVALID_SOCKET) return; // No socket available
        m_hbRunning = true;

        std::thread([this]() {
            SOCKET s = m_hbSocket; // Use existing socket from CheckBanStatus
            
            // Derive session key: key' = HMAC_SHA256(secretKey, hwid|nonce)
            std::string sessionKey = HmacSha256(m_secretKey, m_hwid + ":" + std::to_string(m_sessionNonce));

            // Heartbeat loop: receive Ping, reply Pong
            Oblivion::HeartbeatConfig cfg;
            // Optional client-side overrides
            auto readEnvUint = [](const char* name, uint32_t defVal){
                char buf[64]; DWORD n = GetEnvironmentVariableA(name, buf, sizeof(buf));
                if (n == 0 || n >= sizeof(buf)) return defVal; 
                try { return (uint32_t)std::stoul(std::string(buf)); } catch (...) { return defVal; }
            };
            cfg.interval_ms = readEnvUint("OBLV_HB_INTERVAL_MS", cfg.interval_ms);
            cfg.jitter_ms = readEnvUint("OBLV_HB_JITTER_MS", cfg.jitter_ms);
            cfg.timeout_ms = readEnvUint("OBLV_HB_TIMEOUT_MS", cfg.timeout_ms);
            uint32_t lastSeq = 0;
            while (m_hbRunning) {
                // Wait for server ping line: PING:seq:ts:nonce;
                char buf[256] = {0};
                int n = recv(s, buf, sizeof(buf)-1, 0);
                if (n <= 0) break;
                std::string msg(buf, n);
                
                // Handle multiple PING messages in one recv (buffer may contain multiple messages)
                size_t pos = 0;
                while (pos < msg.length()) {
                    size_t pingStart = msg.find("PING:", pos);
                    if (pingStart == std::string::npos) break;
                    
                    size_t pingEnd = msg.find(';', pingStart);
                    if (pingEnd == std::string::npos) break;
                    
                    std::string singlePing = msg.substr(pingStart, pingEnd - pingStart);
                    
                    // Parse this single PING
                    // PING:seq:ts:nonce
                    size_t p1 = singlePing.find(':');
                    size_t p2 = singlePing.find(':', p1+1);
                    size_t p3 = singlePing.find(':', p2+1);
                    if (p1!=std::string::npos && p2!=std::string::npos && p3!=std::string::npos) {
                        try {
                            uint32_t seq = std::stoul(singlePing.substr(p1+1, p2-p1-1));
                            uint64_t ts = std::stoull(singlePing.substr(p2+1, p3-p2-1));
                            uint64_t nonce = std::stoull(singlePing.substr(p3+1)); // Ambil sisanya setelah p3
                            lastSeq = seq;

                            // Build client status (fallback true for now)
                            Oblivion::ClientStatus st{true, true};
                            // Compose data string for HMAC
                            std::string data = std::to_string(seq) + ":" + std::to_string(ts) + ":" + std::to_string(nonce) + ":" + m_hwid;
                            std::string hmac = HmacSha256(sessionKey, data);

                            // Send PONG line: PONG:seq:ts_client:nonce:statusAS|statusIG:hwid:hmac;
                            uint64_t t_client = (uint64_t)GetTickCount64();
                            std::string statusStr = std::string(st.antiSuspendOk?"1":"0") + std::string("|") + (st.integrityOk?"1":"0");
                            std::string pong = "PONG:" + std::to_string(seq) + ":" + std::to_string(t_client) + ":" + std::to_string(nonce) + ":" + statusStr + ":" + m_hwid + ":" + hmac + ";";
                            send(s, pong.c_str(), (int)pong.length(), 0);
                        } catch (const std::exception&) {
                            // Parse error, skip this PING
                        }
                    }
                    
                    pos = pingEnd + 1;
                }
            }
            closesocket(s);
            m_hbSocket = INVALID_SOCKET;
            m_hbRunning = false;
        }).detach();
    }

    void NetworkReporter::StopHeartbeat() {
        m_hbRunning = false;
        // Beri waktu untuk thread cleanup
        Sleep(100);
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
        int bytesSent = send(connectSocket, report.c_str(), (int)report.length(), 0);
        if (bytesSent == SOCKET_ERROR || bytesSent == 0) {
            // Gagal mengirim laporan - Fail-Closed
            closesocket(connectSocket);
            MessageBoxW(NULL, L"Gagal mengirim laporan ke server.\n\nClient akan ditutup.", L"Oblivion Hack Shield - Error", MB_OK | MB_ICONERROR | MB_TOPMOST);
            ExitProcess(1);
        }

        // Tunggu respons dari server dengan timeout
        char recvbuf[512] = { 0 };
        int recvbuflen = 512;
        fd_set fdset;
        struct timeval tv;
        tv.tv_sec = 3; // Timeout 3 detik
        tv.tv_usec = 0;
        FD_ZERO(&fdset);
        FD_SET(connectSocket, &fdset);

            int selectResult = select(0, &fdset, NULL, NULL, &tv);
            if (selectResult > 0) {
                int bytesReceived = recv(connectSocket, recvbuf, recvbuflen, 0);
                if (bytesReceived > 0) {
                    // Parse response (hilangkan null terminator dan whitespace)
                    std::string response(recvbuf, bytesReceived);
                    // Trim whitespace dan null characters dari awal
                    size_t start = response.find_first_not_of(" \t\n\r\0");
                    if (start != std::string::npos) {
                        response = response.substr(start);
                    }
                    // Trim dari akhir
                    size_t end = response.find_last_not_of(" \t\n\r\0");
                    if (end != std::string::npos) {
                        response = response.substr(0, end + 1);
                    }
                    
                    // Cleanup socket sebelum ExitProcess
                    closesocket(connectSocket);
                    
                    // Cek apakah response adalah "KICK;" (case-sensitive sesuai server)
                    if (response == "KICK;") {
                        // Server mengirim perintah KICK - tampilkan message dan tutup
                        MessageBoxW(NULL, L"Server mendeteksi pelanggaran.\n\nClient akan ditutup.", L"Oblivion Hack Shield - Violation", MB_OK | MB_ICONERROR | MB_TOPMOST);
                        ExitProcess(0);
                    }
                }
            }
        else {
            // Timeout atau error, juga dianggap pelanggaran (Fail-Closed)
            closesocket(connectSocket);
            MessageBoxW(NULL, L"Timeout menunggu respons server.\n\nClient akan ditutup.", L"Oblivion Hack Shield - Error", MB_OK | MB_ICONERROR | MB_TOPMOST);
            ExitProcess(0);
        }

        // Cleanup socket (jika masih terbuka)
        closesocket(connectSocket);
    }
}