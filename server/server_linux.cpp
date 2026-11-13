// Cross-platform server implementation
// Compile with: g++ -std=c++17 -o server server_linux.cpp src/secret_obf.cpp -lssl -lcrypto -lpthread

#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <algorithm>
#include <atomic>
#include <cstring>
#include <cstdlib>
#include <cerrno>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/select.h>
#include <sys/time.h>
#include <limits.h>
#include <limits>
#include <mutex>
#include <stdexcept>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include "secret_obf.h"
#include "include/heartbeat_protocol.h"
#include "include/socket_framing.h"

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <windows.h>
    #include <bcrypt.h>
    #pragma comment(lib, "Ws2_32.lib")
    #pragma comment(lib, "Bcrypt.lib")
    typedef SOCKET SocketType;
    #define INVALID_SOCKET_VAL INVALID_SOCKET
    #define SOCKET_ERROR_VAL SOCKET_ERROR
    #define closesocket_impl closesocket
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <netdb.h>
    #include <unistd.h>
    typedef int SocketType;
    #define INVALID_SOCKET_VAL -1
    #define SOCKET_ERROR_VAL -1
    #define closesocket_impl close
#endif

#define DEFAULT_PORT "54321"
#define BUFFER_LEN 4096
#define MAX_TYPE_LEN 64
#define MAX_DETAILS_LEN 2048
#define MAX_HWID_LEN 128
#define MAX_SECRET_LEN 128

static std::string SERVER_SECRET = OblivionServer::GetServerSecret();
#define BAN_LIST_FILE "bans.txt"
#define VIOLATION_LOG_FILE "violations.log"

static std::mutex g_violationLogMutex;

static std::atomic<uint32_t> g_activeClientCount{ 0 };
static constexpr uint32_t kMaxConcurrentClients = 256;

struct ActiveClientGuard {
    std::atomic<uint32_t>& counter;
    ~ActiveClientGuard() { counter.fetch_sub(1, std::memory_order_relaxed); }
};

static Oblivion::HeartbeatConfig GLOBAL_HB_CONFIG;

bool ConstantTimeEquals(const std::string& left, const std::string& right) {
    if (left.size() != 64 || right.size() != 64) return false;
    unsigned char difference = 0;
    for (size_t i = 0; i < left.size(); ++i) {
        difference |= static_cast<unsigned char>(left[i] ^ right[i]);
    }
    return difference == 0;
}

// Cross-platform helper functions
std::string GetExecutableDirectory() {
#ifdef _WIN32
    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    std::string path(exePath);
    size_t lastSlash = path.find_last_of("\\/");
    if (lastSlash != std::string::npos) {
        return path.substr(0, lastSlash + 1);
    }
    return "";
#else
    char exePath[PATH_MAX];
    ssize_t count = readlink("/proc/self/exe", exePath, PATH_MAX);
    if (count != -1) {
        std::string path(exePath, count);
        size_t lastSlash = path.find_last_of("/");
        if (lastSlash != std::string::npos) {
            return path.substr(0, lastSlash + 1);
        }
    }
    return "./";
#endif
}

std::string GetFilePath(const std::string& filename) {
    std::string exeDir = GetExecutableDirectory();
    return exeDir + filename;
}

std::string GetCurrentTimestamp() {
    auto now = std::time(nullptr);
    struct tm tm_buf;
#ifdef _WIN32
    localtime_s(&tm_buf, &now);
#else
    struct tm* result = localtime_r(&now, &tm_buf);
    if (!result) {
        // Fallback to empty timestamp on error
        return "1970-01-01 00:00:00";
    }
#endif
    std::ostringstream oss;
    oss << std::put_time(&tm_buf, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

int strcasecmp_impl(const char* s1, const char* s2) {
#ifdef _WIN32
    return _stricmp(s1, s2);
#else
    return strcasecmp(s1, s2);
#endif
}

uint64_t GetTickCount64_impl() {
#ifdef _WIN32
    return GetTickCount64();
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)(ts.tv_sec * 1000ULL + ts.tv_nsec / 1000000ULL);
#endif
}

void Sleep_impl(uint32_t ms) {
#ifdef _WIN32
    Sleep(ms);
#else
    usleep(ms * 1000);
#endif
}

// HMAC-SHA256 implementation
std::string hmacSha256(const std::string& key, const std::string& data) {
#ifdef _WIN32
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    NTSTATUS st = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC);
    if (st != 0) return std::string();
    
    DWORD objLen = 0, dlen = 0;
    st = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objLen, sizeof(DWORD), &dlen, 0);
    if (st != 0 || objLen == 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return std::string();
    }
    std::vector<UCHAR> obj(objLen);
    st = BCryptCreateHash(hAlg, &hHash, obj.data(), objLen, (PUCHAR)key.data(), (ULONG)key.size(), 0);
    if (st != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return std::string();
    }
    st = BCryptHashData(hHash, (PUCHAR)data.data(), (ULONG)data.size(), 0);
    if (st != 0) {
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return std::string();
    }
    UCHAR hash[32];
    st = BCryptFinishHash(hHash, hash, sizeof(hash), 0);
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    if (st != 0) return std::string();
    
    static const char* hex = "0123456789abcdef";
    std::string out;
    out.reserve(64);
    for (int i = 0; i < 32; ++i) {
        out.push_back(hex[(hash[i] >> 4) & 0xF]);
        out.push_back(hex[hash[i] & 0xF]);
    }
    return out;
#else
    unsigned char digest[32]{};
    unsigned int digest_len = 0;
    if (!HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
              reinterpret_cast<const unsigned char*>(data.data()), data.size(),
              digest, &digest_len) || digest_len != sizeof(digest)) {
        return std::string();
    }
    
    static const char* hex = "0123456789abcdef";
    std::string out;
    out.reserve(64);
    for (int i = 0; i < 32; ++i) {
        out.push_back(hex[(digest[i] >> 4) & 0xF]);
        out.push_back(hex[digest[i] & 0xF]);
    }
    return out;
#endif
}

bool IsHWIDBanned(const std::string& hwid) {
    std::string banFilePath = GetFilePath(BAN_LIST_FILE);
    std::ifstream banFile(banFilePath);
    if (!banFile.is_open()) {
        return false;
    }
    
    std::string line;
    while (std::getline(banFile, line)) {
        // Skip empty/whitespace-only lines before trimming to avoid npos arithmetic.
        const size_t firstNonWhitespace = line.find_first_not_of(" \t\n\r");
        if (firstNonWhitespace == std::string::npos) {
            continue;
        }
        const size_t lastNonWhitespace = line.find_last_not_of(" \t\n\r");
        line = line.substr(firstNonWhitespace, lastNonWhitespace - firstNonWhitespace + 1);
        
        if (line.empty() || line[0] == '#') {
            continue;
        }
        
        if (strcasecmp_impl(line.c_str(), hwid.c_str()) == 0) {
            banFile.close();
            return true;
        }
    }
    
    banFile.close();
    return false;
}

void AddToBanList(const std::string& hwid) {
    if (IsHWIDBanned(hwid)) {
        return;
    }
    
    std::string banFilePath = GetFilePath(BAN_LIST_FILE);
    std::ofstream banFile(banFilePath, std::ios::app);
    if (banFile.is_open()) {
        banFile << hwid << std::endl;
        banFile.close();
        std::cout << "[BAN] HWID [" << hwid << "] ditambahkan ke ban list." << std::endl;
    } else {
        std::cerr << "[ERROR] Gagal membuka file ban list untuk menulis." << std::endl;
    }
}

// Helper function untuk extract file/software name dari details
std::string ExtractDetectedFile(const std::string& type, const std::string& details) {
    std::string detectedFile = "UNKNOWN";
    
    // Untuk PROCESS_DETECTED, details biasanya berisi nama process
    if (type == "PROCESS_DETECTED") {
        // Details biasanya berisi nama file .exe
        size_t dotExe = details.find(".exe");
        if (dotExe != std::string::npos) {
            size_t start = details.rfind(' ', dotExe);
            if (start == std::string::npos) start = 0;
            else start++;
            detectedFile = details.substr(start, dotExe - start + 4);
        } else {
            detectedFile = details; // Ambil seluruh details jika tidak ada .exe
        }
    }
    // Untuk INJECTION_DETECTED, details berisi nama DLL
    else if (type == "INJECTION_DETECTED") {
        size_t dotDll = details.find(".dll");
        if (dotDll != std::string::npos) {
            size_t start = details.rfind(' ', dotDll);
            if (start == std::string::npos) start = 0;
            else start++;
            detectedFile = details.substr(start, dotDll - start + 4);
        } else {
            detectedFile = details;
        }
    }
    // Untuk UNTRUSTED_MODULE, extract nama modul dari details
    else if (type == "UNTRUSTED_MODULE") {
        // Format: "Module: WpeSpy.dll | Path: H:\..."
        size_t modulePos = details.find("Module: ");
        if (modulePos != std::string::npos) {
            size_t start = modulePos + 8; // len("Module: ")
            size_t end = details.find(" | ", start);
            if (end != std::string::npos) {
                detectedFile = details.substr(start, end - start);
            } else {
                detectedFile = details.substr(start);
                // Truncate jika terlalu panjang
                if (detectedFile.length() > 100) {
                    detectedFile = detectedFile.substr(0, 100);
                }
            }
        } else {
            // Fallback: cari .dll dalam details
            size_t dotDll = details.find(".dll");
            if (dotDll != std::string::npos) {
                size_t start = details.rfind(' ', dotDll);
                if (start == std::string::npos) start = 0;
                else start++;
                detectedFile = details.substr(start, dotDll - start + 4);
            } else {
                detectedFile = details.length() > 100 ? details.substr(0, 100) + "..." : details;
            }
        }
    }
    // Untuk FILE_MODIFIED atau FILE_INTEGRITY_FAILED, extract nama file
    else if (type == "FILE_MODIFIED" || type == "FILE_INTEGRITY_FAILED") {
        // Format biasanya: "filename.ext - Hash mismatch..." atau "filename.ext - File not found"
        size_t dash = details.find(" - ");
        if (dash != std::string::npos) {
            detectedFile = details.substr(0, dash);
        } else {
            detectedFile = details;
        }
    }
    // Untuk ADV_HEURISTIC_DETECTED, extract process name
    else if (type == "ADV_HEURISTIC_DETECTED") {
        // Format: "[DETECTION_TYPE] processName.exe (PID:123) => indicator"
        size_t bracket = details.find(']');
        if (bracket != std::string::npos) {
            size_t spaceAfter = details.find(' ', bracket + 1);
            if (spaceAfter != std::string::npos) {
                size_t spaceBeforePid = details.find(" (PID:", spaceAfter);
                if (spaceBeforePid != std::string::npos) {
                    detectedFile = details.substr(spaceAfter + 1, spaceBeforePid - spaceAfter - 1);
                } else {
                    // Fallback: ambil setelah bracket sampai spasi berikutnya
                    detectedFile = details.substr(spaceAfter + 1);
                    size_t nextSpace = detectedFile.find(' ');
                    if (nextSpace != std::string::npos) {
                        detectedFile = detectedFile.substr(0, nextSpace);
                    }
                }
            }
        }
        // Fallback: cari .exe dalam details
        if (detectedFile == "UNKNOWN") {
            size_t dotExe = details.find(".exe");
            if (dotExe != std::string::npos) {
                size_t start = details.rfind(' ', dotExe);
                if (start == std::string::npos) start = 0;
                else start++;
                detectedFile = details.substr(start, dotExe - start + 4);
            }
        }
    }
    // Untuk OVERLAY_DETECTED, details berisi window class name
    else if (type == "OVERLAY_DETECTED") {
        detectedFile = "Overlay Window: " + details;
    }
    // Untuk SIGNATURE_SPOOFING, extract process name dari details
    else if (type == "SIGNATURE_SPOOFING") {
        // Format: "Process: processName.exe (PID:123) | Path: ... | Expected: ... | Actual: ..."
        size_t processPos = details.find("Process: ");
        if (processPos != std::string::npos) {
            size_t start = processPos + 9; // len("Process: ")
            size_t end = details.find(" (PID:", start);
            if (end != std::string::npos) {
                detectedFile = details.substr(start, end - start);
            } else {
                size_t spaceAfter = details.find(' ', start);
                if (spaceAfter != std::string::npos) {
                    detectedFile = details.substr(start, spaceAfter - start);
                } else {
                    detectedFile = details.substr(start);
                }
            }
        } else {
            // Fallback: cari .exe dalam details
            size_t dotExe = details.find(".exe");
            if (dotExe != std::string::npos) {
                size_t start = details.rfind(' ', dotExe);
                if (start == std::string::npos) start = 0;
                else start++;
                detectedFile = details.substr(start, dotExe - start + 4);
            } else {
                detectedFile = details.length() > 100 ? details.substr(0, 100) + "..." : details;
            }
        }
    }
    // Untuk CODE_MODIFICATION, EARLY_INJECTION, CODE_CAVE_DETECTED, SUSPICIOUS_MEMORY
    else if (type == "CODE_MODIFICATION" || type == "EARLY_INJECTION" || 
             type == "CODE_CAVE_DETECTED" || type == "SUSPICIOUS_MEMORY") {
        // Format: "File: filename.exe | Section: ... | ..." atau "File: filename.exe | ..."
        size_t filePos = details.find("File: ");
        if (filePos != std::string::npos) {
            size_t start = filePos + 6; // len("File: ")
            size_t end = details.find(" | ", start);
            if (end != std::string::npos) {
                detectedFile = details.substr(start, end - start);
            } else {
                // Jika tidak ada " | ", ambil sampai akhir string atau sampai karakter tertentu
                size_t spaceAfter = details.find(' ', start);
                if (spaceAfter != std::string::npos && spaceAfter < start + 200) {
                    detectedFile = details.substr(start, spaceAfter - start);
                } else {
                    detectedFile = details.substr(start);
                    if (detectedFile.length() > 100) {
                        detectedFile = detectedFile.substr(0, 100);
                    }
                }
            }
        } else {
            // Fallback untuk format lama
            size_t dotExe = details.find(".exe");
            if (dotExe != std::string::npos) {
                size_t start = details.rfind(' ', dotExe);
                if (start == std::string::npos) start = 0;
                else start++;
                detectedFile = details.substr(start, dotExe - start + 4);
            } else {
                detectedFile = details.length() > 100 ? details.substr(0, 100) + "..." : details;
            }
        }
    }
    // Untuk deteksi lain, coba extract dari details
    else {
        // Coba cari .exe atau .dll dalam details
        size_t dotExe = details.find(".exe");
        size_t dotDll = details.find(".dll");
        
        if (dotExe != std::string::npos && (dotDll == std::string::npos || dotExe < dotDll)) {
            size_t start = details.rfind(' ', dotExe);
            if (start == std::string::npos) start = 0;
            else start++;
            detectedFile = details.substr(start, dotExe - start + 4);
        } else if (dotDll != std::string::npos) {
            size_t start = details.rfind(' ', dotDll);
            if (start == std::string::npos) start = 0;
            else start++;
            detectedFile = details.substr(start, dotDll - start + 4);
        } else {
            // Jika tidak ada, gunakan detail lengkap (mungkin sudah jelas)
            detectedFile = details.length() > 100 ? details.substr(0, 100) + "..." : details;
        }
    }
    
    return detectedFile;
}

void LogViolation(const std::string& type, const std::string& details, const std::string& hwid) {
    std::lock_guard<std::mutex> lock(g_violationLogMutex);
    std::string logFilePath = GetFilePath(VIOLATION_LOG_FILE);
    std::ofstream logFile(logFilePath, std::ios::app);
    if (logFile.is_open()) {
        // Extract file/software yang terdeteksi
        std::string detectedFile = ExtractDetectedFile(type, details);
        
        // Log dengan format yang lebih jelas
        logFile << "[" << GetCurrentTimestamp() << "] TYPE: " << type 
                << " | HWID: " << hwid 
                << " | DETECTED_FILE/SOFTWARE: " << detectedFile
                << " | DETAILS: " << details << std::endl;
        logFile.close();
        
        // Also log to console dengan format yang jelas
        std::cout << "[VIOLATION] TYPE: " << type 
                  << " | HWID: " << hwid 
                  << " | FILE/SOFTWARE: " << detectedFile << std::endl;
    } else {
        std::cerr << "[ERROR] Gagal membuka file log untuk menulis." << std::endl;
    }
}

bool IsSeriousViolation(const std::string& type) {
    std::vector<std::string> seriousViolations = {
        "MEMORY_VIOLATION",
        "INJECTION_DETECTED",
        "FILE_MODIFIED",
        "FILE_INTEGRITY_FAILED",
        "SIGNATURE_SPOOFING",
        "ADV_HEURISTIC_DETECTED",
        "PROCESS_DETECTED"
    };
    
    for (const auto& serious : seriousViolations) {
        if (strcasecmp_impl(type.c_str(), serious.c_str()) == 0) {
            return true;
        }
    }
    
    return false;
}

std::string ExtractHWIDFromRawData(const std::string& rawData) {
    size_t firstColon = rawData.find(':');
    if (firstColon == std::string::npos) return "UNKNOWN";
    
    size_t secondColon = rawData.find(':', firstColon + 1);
    if (secondColon == std::string::npos) return "UNKNOWN";
    
    size_t thirdColon = rawData.find(':', secondColon + 1);
    if (thirdColon == std::string::npos) return "UNKNOWN";
    
    std::string hwid = rawData.substr(secondColon + 1, thirdColon - secondColon - 1);
    
    if (hwid.empty() || hwid.length() > MAX_HWID_LEN) return "UNKNOWN";
    
    std::string sanitizedHwid;
    for (char c : hwid) {
        if (std::isalnum(static_cast<unsigned char>(c)) || c == '-') {
            sanitizedHwid += c;
        }
    }
    
    return sanitizedHwid.empty() ? "UNKNOWN" : sanitizedHwid;
}

std::string SanitizeInput(const std::string& input, size_t maxLen) {
    std::string sanitized;
    size_t reserveSize = input.length() < maxLen ? input.length() : maxLen;
    sanitized.reserve(reserveSize);
    
    for (size_t i = 0; i < input.length() && sanitized.length() < maxLen; i++) {
        char c = input[i];
        // Strip CR/LF/TAB so untrusted reports cannot forge log lines.
        if (c >= 0x20 && c <= 0x7E) {
            if (c != '<' && c != '>' && c != '&' && c != '"' && c != '\'') {
                sanitized += c;
            }
        }
    }
    
    return sanitized;
}

struct ParsedReport {
    bool valid = false;
    std::string type;
    std::string details;
    std::string hwid;
    std::string challengeNonce;
    std::string mac;
    std::string errorMessage;
};

static bool IsValidChallengeNonce(const std::string& nonce) {
    if (nonce.empty() || nonce.size() > 20 ||
        !std::all_of(nonce.begin(), nonce.end(),
            [](unsigned char c) { return c >= '0' && c <= '9'; })) {
        return false;
    }
    try {
        size_t parsed = 0;
        const unsigned long long value = std::stoull(nonce, &parsed, 10);
        return parsed == nonce.size() && value != 0;
    } catch (...) {
        return false;
    }
}

ParsedReport ParseProtocol(const std::string& report) {
    ParsedReport result;
    if (report.length() < 12) {
        result.errorMessage = "Report too short";
        return result;
    }
    if (report.length() > BUFFER_LEN - 1) {
        result.errorMessage = "Report exceeds maximum length";
        return result;
    }
    if (report.back() != ';') {
        result.errorMessage = "Report must end with semicolon";
        return result;
    }
    if (std::count(report.begin(), report.end(), ':') != 4) {
        result.errorMessage = "Invalid format: expected 4 colons";
        return result;
    }

    const size_t pos1 = report.find(':');
    const size_t pos2 = report.find(':', pos1 + 1);
    const size_t pos3 = report.find(':', pos2 + 1);
    const size_t pos4 = report.find(':', pos3 + 1);
    const size_t pos5 = report.find(';', pos4 + 1);
    if (pos1 == 0 || pos2 == std::string::npos || pos3 == std::string::npos ||
        pos4 == std::string::npos || pos5 != report.size() - 1 ||
        pos4 == pos5 - 1) {
        result.errorMessage = "Invalid request field positions";
        return result;
    }

    result.type = report.substr(0, pos1);
    result.details = report.substr(pos1 + 1, pos2 - pos1 - 1);
    result.hwid = report.substr(pos2 + 1, pos3 - pos2 - 1);
    result.challengeNonce = report.substr(pos3 + 1, pos4 - pos3 - 1);
    result.mac = report.substr(pos4 + 1, pos5 - pos4 - 1);

    if (result.type.empty() || result.type.length() > MAX_TYPE_LEN ||
        result.details.length() > MAX_DETAILS_LEN ||
        result.hwid.empty() || result.hwid.length() > MAX_HWID_LEN ||
        !IsValidChallengeNonce(result.challengeNonce) ||
        result.mac.size() != 64) {
        result.errorMessage = "Request field length or value is invalid";
        return result;
    }
    for (unsigned char c : result.type) {
        if (!std::isalnum(c) && c != '_') {
            result.errorMessage = "TYPE field contains invalid characters";
            return result;
        }
    }
    for (unsigned char c : result.hwid) {
        if (!std::isxdigit(c) && c != '-') {
            result.errorMessage = "HWID field contains invalid characters";
            return result;
        }
    }

    result.valid = true;
    return result;
}


void HandleClient(SocketType clientSocket) {
    const uint32_t activeBefore = g_activeClientCount.fetch_add(1, std::memory_order_relaxed);
    if (activeBefore >= kMaxConcurrentClients) {
        g_activeClientCount.fetch_sub(1, std::memory_order_relaxed);
        const char* busyResponse = "BUSY;";
        OblivionNet::SendAll(clientSocket, busyResponse, strlen(busyResponse));
        closesocket_impl(clientSocket);
        return;
    }
    ActiveClientGuard activeGuard{ g_activeClientCount };
    std::string extractedHwid = "UNKNOWN";
    std::string pendingNetworkData;
    std::string report;

    try {
        if (!OblivionNet::ReceiveFrame(clientSocket, pendingNetworkData,
                                       report, 5000, BUFFER_LEN - 1)) {
            LogViolation("FRAME_READ_FAILED", "Timed out or received an oversized/incomplete HELLO request", extractedHwid);
            closesocket_impl(clientSocket);
            return;
        }

        std::string helloHwid;
        if (!ParseHelloFrame(report, helloHwid) || !pendingNetworkData.empty()) {
            LogViolation("MALFORMED_REQUEST", "Expected one HELLO:<HWID>; frame", extractedHwid);
            closesocket_impl(clientSocket);
            return;
        }
        extractedHwid = helloHwid;

        uint64_t challengeNonceValue = 0;
        if (!OblivionNet::GenerateSecureNonce(challengeNonceValue)) {
            LogViolation("RNG_FAILURE", "Unable to generate request challenge nonce", helloHwid);
            closesocket_impl(clientSocket);
            return;
        }
        const std::string challengeNonce = std::to_string(challengeNonceValue);
        const std::string challengeMac =
            hmacSha256(
                SERVER_SECRET, "CHALLENGE:" + helloHwid + ":" + challengeNonce);
        if (challengeMac.size() != 64) {
            LogViolation("AUTH_CRYPTO_FAILURE", "Unable to authenticate request challenge", helloHwid);
            closesocket_impl(clientSocket);
            return;
        }
        const std::string challengeResponse =
            "CHALLENGE:" + challengeNonce + ":" + challengeMac + ";";
        if (!OblivionNet::SendAll(clientSocket, challengeResponse.data(), challengeResponse.size())) {
            closesocket_impl(clientSocket);
            return;
        }

        report.clear();
        pendingNetworkData.clear();
        if (!OblivionNet::ReceiveFrame(clientSocket, pendingNetworkData,
                                       report, 5000, BUFFER_LEN - 1)) {
            LogViolation("FRAME_READ_FAILED", "Timed out or received an incomplete authenticated request", helloHwid);
            closesocket_impl(clientSocket);
            return;
        }
        if (!pendingNetworkData.empty()) {
            LogViolation("MALFORMED_REQUEST", "Unexpected bytes after authenticated request frame", helloHwid);
            closesocket_impl(clientSocket);
            return;
        }

        const ssize_t bytesReceived = static_cast<ssize_t>(report.size());
        if (bytesReceived > 0) {
            std::cout << "[DEBUG] Received authenticated request (" << bytesReceived
                      << " bytes) from HWID: " << extractedHwid << std::endl;

            ParsedReport parsed = ParseProtocol(report);
            
            if (!parsed.valid) {
                std::cout << "[ERROR] Invalid protocol format: " << parsed.errorMessage << std::endl;
                std::cout << "[DEBUG] Expected format: TYPE:DETAILS:HWID:NONCE:MAC;" << std::endl;
                
                // Never log raw untrusted protocol bytes; they may contain control characters.
                LogViolation("MALFORMED_REQUEST", parsed.errorMessage, extractedHwid);
                
                const char* errorResponse = "ERROR:INVALID_FORMAT;";
                OblivionNet::SendAll(clientSocket, errorResponse, strlen(errorResponse));
                closesocket_impl(clientSocket);
                return;
            }
            
            const std::string type = parsed.type;
            const std::string details = SanitizeInput(parsed.details, MAX_DETAILS_LEN);
            const std::string hwid = parsed.hwid;
            const std::string expectedRequestMac = hmacSha256(
                SERVER_SECRET,
                BuildRequestAuthData(type, parsed.details, hwid, challengeNonce));
            const bool requestAuthenticated =
                hwid == helloHwid && parsed.challengeNonce == challengeNonce &&
                ConstantTimeEquals(expectedRequestMac, parsed.mac);

            std::cout << "[PARSE] TYPE: " << type << " | HWID: " << hwid
                      << " | DETAILS_LEN: " << details.length() << std::endl;

            if (!requestAuthenticated) {
                LogViolation("AUTH_FAILED", "Invalid challenge-response MAC", hwid);
                const char* kickCommand = "KICK;";
                OblivionNet::SendAll(clientSocket, kickCommand, strlen(kickCommand));
                closesocket_impl(clientSocket);
                return;
            }
            else if (type == "CHECKIN") {
                std::cout << "[CHECKIN] Client check-in dari HWID [" << hwid << "]" << std::endl;
                
                bool isBanned = IsHWIDBanned(hwid);
                
                if (isBanned) {
                    const char* kickCommand = "KICK;";
                    OblivionNet::SendAll(clientSocket, kickCommand, strlen(kickCommand));
                    std::cout << "[BAN] HWID [" << hwid << "] terdeteksi di ban list. Perintah KICK dikirim." << std::endl;
                    std::cout << "[INFO] Untuk unban, hapus HWID dari bans.txt dan restart client." << std::endl;
                } else {
                    Oblivion::HeartbeatConfig cfg = GLOBAL_HB_CONFIG;
                    uint64_t sessionNonce = 0;
                    if (!OblivionNet::GenerateSecureNonce(sessionNonce)) {
                        LogViolation("RNG_FAILURE", "Unable to generate secure session nonce", hwid);
                        closesocket_impl(clientSocket);
                        return;
                    }
                    const std::string sessionNonceText = std::to_string(sessionNonce);
                    const std::string sessionAuthData =
                        "SESSION:" + hwid + ":" + challengeNonce + ":" + sessionNonceText + ":" +
                        std::to_string(cfg.interval_ms) + ":" + std::to_string(cfg.timeout_ms);
                    const std::string sessionAuthMac = hmacSha256(SERVER_SECRET, sessionAuthData);
                    if (sessionAuthMac.size() != 64) {
                        LogViolation("AUTH_CRYPTO_FAILURE", "Unable to authenticate session configuration", hwid);
                        closesocket_impl(clientSocket);
                        return;
                    }
                    std::string response = "OK;SESSION_NONCE:" + sessionNonceText +
                                           ";HB_CONFIG:" + std::to_string(cfg.interval_ms) +
                                           ":" + std::to_string(cfg.timeout_ms) +
                                           ";SESSION_AUTH:" + sessionAuthMac + ";";
                    if (!OblivionNet::SendAll(clientSocket, response.data(), response.size())) {
                        closesocket_impl(clientSocket);
                        return;
                    }
                    std::cout << "[OK] HWID [" << hwid << "] diizinkan. Memulai heartbeat ping." << std::endl;

                    uint32_t seq = 1;
                    uint32_t consecutiveMiss = 0;
                    uint64_t rttSum = 0; uint32_t rttCount = 0; 
                    uint64_t rttSumCumulative = 0; uint64_t rttCountCumulative = 0; 
                    uint32_t totalMisses = 0;
                    enum class HbState { Healthy, Warning, Flagged } state = HbState::Healthy;

                    std::string sessionKey = hmacSha256(SERVER_SECRET, hwid + ":" + std::to_string(sessionNonce));
                    if (sessionKey.size() != 64) {
                        LogViolation("HB_CRYPTO_FAILURE", "Unable to derive heartbeat session key", hwid);
                        closesocket_impl(clientSocket);
                        return;
                    }
                    
                    std::cout << "[HEARTBEAT] Started for HWID [" << hwid << "]" << std::endl;

                    while (true) {
                        uint64_t ping_ts = GetTickCount64_impl();
                        uint64_t ping_nonce = 0;
                        if (!OblivionNet::GenerateSecureNonce(ping_nonce)) {
                            LogViolation("RNG_FAILURE", "Unable to generate secure heartbeat nonce", hwid);
                            break;
                        }
                        std::string ping = "PING:" + std::to_string(seq) + ":" + std::to_string(ping_ts) + ":" + std::to_string(ping_nonce) + ";";
                        if (!OblivionNet::SendAll(clientSocket, ping.data(), ping.size())) { 
                            std::cout << "[HEARTBEAT] Connection closed for HWID [" << hwid << "] - send failed" << std::endl; 
                            break; 
                        }

                        std::string pongFrame;
                        if (OblivionNet::ReceiveFrame(clientSocket, pendingNetworkData,
                                                      pongFrame, cfg.timeout_ms, 512)) {
                            if (pongFrame.rfind("PONG:", 0) == 0 && pongFrame.back() == ';') {
                                const std::string resp = pongFrame.substr(0, pongFrame.size() - 1);
                                std::vector<size_t> col;
                                size_t pos = 0;
                                while ((pos = resp.find(':', pos)) != std::string::npos) {
                                    col.push_back(pos);
                                    ++pos;
                                }

                                if (col.size() == 6) {
                                    try {
                                        const std::string seqText = resp.substr(col[0] + 1, col[1] - col[0] - 1);
                                        const std::string clientTsText = resp.substr(col[1] + 1, col[2] - col[1] - 1);
                                        const std::string nonceText = resp.substr(col[2] + 1, col[3] - col[2] - 1);
                                        size_t parsedSeq = 0, parsedClientTs = 0, parsedNonce = 0;
                                        const unsigned long long seqValue = std::stoull(seqText, &parsedSeq);
                                        const uint64_t clientTs = std::stoull(clientTsText, &parsedClientTs);
                                        const uint64_t pnonce = std::stoull(nonceText, &parsedNonce);
                                        (void)clientTs;
                                        if (parsedSeq != seqText.size() ||
                                            parsedClientTs != clientTsText.size() ||
                                            parsedNonce != nonceText.size() ||
                                            seqValue > (std::numeric_limits<uint32_t>::max)()) {
                                            throw std::invalid_argument("invalid numeric field");
                                        }

                                        const uint32_t pseq = static_cast<uint32_t>(seqValue);
                                        const std::string status = resp.substr(col[3] + 1, col[4] - col[3] - 1);
                                        const std::string phwid = resp.substr(col[4] + 1, col[5] - col[4] - 1);
                                        const std::string hmac = resp.substr(col[5] + 1);

                                        if (pseq != seq || pnonce != ping_nonce || phwid != hwid ||
                                            status != "1|1") {
                                            ++consecutiveMiss;
                                            ++totalMisses;
                                        } else {
                                            const std::string data = std::to_string(pseq) + ":" +
                                                std::to_string(ping_ts) + ":" +
                                                std::to_string(pnonce) + ":" + phwid;
                                            const std::string expected = hmacSha256(sessionKey, data);
                                            if (!ConstantTimeEquals(expected, hmac)) {
                                                ++consecutiveMiss;
                                                ++totalMisses;
                                            } else {
                                                const uint64_t rtt = GetTickCount64_impl() - ping_ts;
                                                rttSum += rtt;
                                                ++rttCount;
                                                rttSumCumulative += rtt;
                                                ++rttCountCumulative;
                                                consecutiveMiss = 0;
                                                if (state == HbState::Warning) {
                                                    state = HbState::Healthy;
                                                    std::cout << "[HEARTBEAT] Recovery: state->HEALTHY" << std::endl;
                                                }

                                                if (rttCount >= 5) {
                                                    const uint64_t avg = rttSum / rttCount;
                                                    if (avg > cfg.rtt_warn_ms && state == HbState::Healthy) {
                                                        state = HbState::Warning;
                                                        std::cout << "[HB] state->WARNING (avg RTT=" << avg << ")" << std::endl;
                                                        const double avgCumSnap = rttCountCumulative
                                                            ? static_cast<double>(rttSumCumulative) / rttCountCumulative : 0.0;
                                                        LogViolation("HB_WARNING",
                                                            "High average RTT " + std::to_string(avg) +
                                                            "ms | avgCum=" + std::to_string(static_cast<int>(avgCumSnap)) +
                                                            "ms | missesTotal=" + std::to_string(totalMisses), hwid);
                                                    } else if (avg <= cfg.rtt_warn_ms && state != HbState::Healthy) {
                                                        state = HbState::Healthy;
                                                        std::cout << "[HB] state->HEALTHY (avg RTT=" << avg << ")" << std::endl;
                                                    }
                                                    rttSum = 0;
                                                    rttCount = 0;
                                                }
                                            }
                                        }
                                    } catch (...) {
                                        ++consecutiveMiss;
                                        ++totalMisses;
                                    }
                                } else {
                                    ++consecutiveMiss;
                                    ++totalMisses;
                                }
                            } else {
                                ++consecutiveMiss;
                                ++totalMisses;
                            }
                        } else {
                            ++consecutiveMiss;
                            ++totalMisses;
                        }

                        const uint32_t warningThreshold =
                            cfg.max_consecutive_miss > 1 ? cfg.max_consecutive_miss - 1 : cfg.max_consecutive_miss;
                        if (consecutiveMiss >= cfg.max_consecutive_miss) {
                            state = HbState::Flagged;
                            const double avgCumSnap = rttCountCumulative
                                ? static_cast<double>(rttSumCumulative) / rttCountCumulative : 0.0;
                            std::cout << "[HEARTBEAT] FLAGGED for HWID [" << hwid << "] - "
                                      << consecutiveMiss << " consecutive misses" << std::endl;
                            LogViolation("HB_FLAGGED",
                                std::to_string(consecutiveMiss) + " consecutive heartbeat misses | avgCum=" +
                                std::to_string(static_cast<int>(avgCumSnap)) + "ms | missesTotal=" +
                                std::to_string(totalMisses), hwid);
                            break;
                        } else if (consecutiveMiss >= warningThreshold && state == HbState::Healthy) {
                            state = HbState::Warning;
                            const double avgCumSnap = rttCountCumulative
                                ? static_cast<double>(rttSumCumulative) / rttCountCumulative : 0.0;
                            std::cout << "[HEARTBEAT] WARNING for HWID [" << hwid << "] - "
                                      << consecutiveMiss << " consecutive misses" << std::endl;
                            LogViolation("HB_WARNING",
                                std::to_string(consecutiveMiss) + " consecutive heartbeat misses | avgCum=" +
                                std::to_string(static_cast<int>(avgCumSnap)) + "ms | missesTotal=" +
                                std::to_string(totalMisses), hwid);
                        }
                        seq++;
                        Sleep_impl(cfg.interval_ms);
                    }
                }
            } else {
                std::cout << "[INFO] Laporan diterima dari HWID [" << hwid << "]: " << type << " - " << details << std::endl;
                
                LogViolation(type, details, hwid);
                
                bool isBanned = IsHWIDBanned(hwid);
                
                if (isBanned) {
                    const char* kickCommand = "KICK;";
                    OblivionNet::SendAll(clientSocket, kickCommand, strlen(kickCommand));
                    std::cout << "[INFO] Perintah KICK dikirim ke client (HWID: " << hwid << ") - sudah ada di ban list." << std::endl;
                } else {
                    const char* acceptedCommand = "OK;";
                    OblivionNet::SendAll(clientSocket, acceptedCommand, strlen(acceptedCommand));
                    std::cout << "[WARNING] Pelanggaran terdeteksi dari HWID [" << hwid
                              << "], dicatat ke log (menunggu review manual)." << std::endl;
                }
            }
        } else if (bytesReceived == 0) {
            std::cout << "[INFO] Client closed connection gracefully" << std::endl;
        } else {
#ifdef _WIN32
            int errorCode = WSAGetLastError();
#else
            int errorCode = errno;
#endif
            std::cout << "[ERROR] recv() failed with error code: " << errorCode << std::endl;
            LogViolation("RECV_ERROR", "Error code: " + std::to_string(errorCode), extractedHwid);
        }
    } catch (const std::exception& e) {
        std::cerr << "[EXCEPTION] Error handling client: " << e.what() << std::endl;
        LogViolation("EXCEPTION", std::string("Exception: ") + e.what(), extractedHwid);
    } catch (...) {
        std::cerr << "[EXCEPTION] Unknown error handling client" << std::endl;
        LogViolation("EXCEPTION", "Unknown exception occurred", extractedHwid);
    }

    closesocket_impl(clientSocket);
}

int main() {
    if (SERVER_SECRET.empty() || SERVER_SECRET == "DEV_SECRET_NOT_SET") {
        std::cerr << "[FATAL] OBLIVION_SECRET is not configured; refusing to start." << std::endl;
        return 1;
    }

#ifdef _WIN32
    WSADATA wsaData;
    int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        std::cerr << "WSAStartup gagal dengan error: " << iResult << std::endl;
        return 1;
    }
#endif

    SocketType ListenSocket = INVALID_SOCKET_VAL;
    SocketType ClientSocket = INVALID_SOCKET_VAL;

    struct addrinfo* result = NULL;
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    int iResult = getaddrinfo(NULL, DEFAULT_PORT, &hints, &result);
    if (iResult != 0) {
        std::cerr << "getaddrinfo gagal dengan error: " << iResult << std::endl;
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }

    ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (ListenSocket == INVALID_SOCKET_VAL) {
        std::cerr << "Socket gagal dibuat" << std::endl;
        freeaddrinfo(result);
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }

    int opt = 1;
#ifdef _WIN32
    setsockopt(ListenSocket, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));
#else
    setsockopt(ListenSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#endif

    iResult = bind(ListenSocket, result->ai_addr, result->ai_addrlen);
    if (iResult == SOCKET_ERROR_VAL) {
        std::cerr << "Bind gagal" << std::endl;
        freeaddrinfo(result);
        closesocket_impl(ListenSocket);
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }

    freeaddrinfo(result);

    iResult = listen(ListenSocket, SOMAXCONN);
    if (iResult == SOCKET_ERROR_VAL) {
        std::cerr << "Listen gagal" << std::endl;
        closesocket_impl(ListenSocket);
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }

    std::cout << "==================================================" << std::endl;
    std::cout << "  OBLIVION HACK SHIELD - Server Component" << std::endl;
    std::cout << "  Version 1.0 - Ragnarok Online Protection" << std::endl;
    std::cout << "==================================================" << std::endl;
    std::cout << "[INFO] Server berjalan dan mendengarkan di port " << DEFAULT_PORT << std::endl;
    std::cout << "[INFO] Ban list file: " << GetFilePath(BAN_LIST_FILE) << std::endl;
    std::cout << "[INFO] Violation log file: " << GetFilePath(VIOLATION_LOG_FILE) << std::endl;
    std::cout << "[INFO] Menunggu koneksi dari client..." << std::endl;
    std::cout << "==================================================" << std::endl;

    auto readEnvUint = [](const char* name, uint32_t defaultValue) {
        const char* envValue = std::getenv(name);
        if (!envValue || !*envValue) return defaultValue;

        errno = 0;
        char* end = nullptr;
        const unsigned long long parsed = std::strtoull(envValue, &end, 10);
        if (errno != 0 || end == envValue || *end != 0 ||
            parsed > (std::numeric_limits<uint32_t>::max)()) {
            std::cerr << "[HB CFG] Invalid value for " << name << "; using default "
                      << defaultValue << std::endl;
            return defaultValue;
        }
        return static_cast<uint32_t>(parsed);
    };

    GLOBAL_HB_CONFIG.interval_ms = readEnvUint("OBLV_HB_INTERVAL_MS", GLOBAL_HB_CONFIG.interval_ms);
    GLOBAL_HB_CONFIG.jitter_ms = readEnvUint("OBLV_HB_JITTER_MS", GLOBAL_HB_CONFIG.jitter_ms);
    GLOBAL_HB_CONFIG.timeout_ms = readEnvUint("OBLV_HB_TIMEOUT_MS", GLOBAL_HB_CONFIG.timeout_ms);
    GLOBAL_HB_CONFIG.max_consecutive_miss = readEnvUint("OBLV_HB_MAX_MISS", GLOBAL_HB_CONFIG.max_consecutive_miss);
    GLOBAL_HB_CONFIG.rtt_warn_ms = readEnvUint("OBLV_HB_RTT_WARN_MS", GLOBAL_HB_CONFIG.rtt_warn_ms);

    if (GLOBAL_HB_CONFIG.interval_ms < 100 || GLOBAL_HB_CONFIG.interval_ms > 60000 ||
        GLOBAL_HB_CONFIG.jitter_ms > 10000 ||
        GLOBAL_HB_CONFIG.timeout_ms < 250 || GLOBAL_HB_CONFIG.timeout_ms > 120000 ||
        GLOBAL_HB_CONFIG.max_consecutive_miss < 1 || GLOBAL_HB_CONFIG.max_consecutive_miss > 10 ||
        GLOBAL_HB_CONFIG.rtt_warn_ms > 60000) {
        std::cerr << "[FATAL] Heartbeat configuration outside supported bounds." << std::endl;
        closesocket_impl(ListenSocket);
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }

    std::cout << "[HB CFG] interval=" << GLOBAL_HB_CONFIG.interval_ms
              << "ms jitter=" << GLOBAL_HB_CONFIG.jitter_ms
              << "ms timeout=" << GLOBAL_HB_CONFIG.timeout_ms
              << "ms maxMiss=" << GLOBAL_HB_CONFIG.max_consecutive_miss
              << " rttWarn=" << GLOBAL_HB_CONFIG.rtt_warn_ms << "ms" << std::endl;

    while (true) {
        ClientSocket = accept(ListenSocket, NULL, NULL);
        if (ClientSocket == INVALID_SOCKET_VAL) {
            std::cerr << "[ERROR] Accept gagal" << std::endl;
            continue;
        }

        std::cout << "\n[CONNECTION] New client connected" << std::endl;
        
        try {
            std::thread clientThread(HandleClient, ClientSocket);
            clientThread.detach();
        } catch (const std::exception& e) {
            std::cerr << "[ERROR] Failed to start client handler thread: " << e.what() << std::endl;
            closesocket_impl(ClientSocket);
        }
    }

    closesocket_impl(ListenSocket);
#ifdef _WIN32
    WSACleanup();
#endif

    return 0;
}

