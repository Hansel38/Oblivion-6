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
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include "secret_obf.h"
#include "include/heartbeat_protocol.h"

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
    (void)BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objLen, sizeof(DWORD), &dlen, 0);
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
    unsigned char digest[32];
    unsigned int digest_len;
    HMAC(EVP_sha256(), key.data(), key.size(),
         (unsigned char*)data.data(), data.size(), digest, &digest_len);
    
    if (digest_len != 32) return std::string();
    
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
        line.erase(0, line.find_first_not_of(" \t\n\r"));
        line.erase(line.find_last_not_of(" \t\n\r") + 1);
        
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
        if ((c >= 0x20 && c <= 0x7E) || c == '\n' || c == '\r' || c == '\t') {
            if (c != '<' && c != '>' && c != '&' && c != '"' && c != '\'') {
                sanitized += c;
            }
        }
    }
    
    return sanitized;
}

struct ParsedReport {
    bool valid = false;
    std::string type = "";
    std::string details = "";
    std::string hwid = "";
    std::string secret = "";
    std::string errorMessage = "";
};

ParsedReport ParseProtocol(const std::string& report) {
    ParsedReport result;
    result.valid = false;
    
    if (report.length() < 10) {
        result.errorMessage = "Report too short (minimum 10 characters required)";
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
    
    size_t colonCount = std::count(report.begin(), report.end(), ':');
    if (colonCount != 3) {
        result.errorMessage = "Invalid format: expected 3 colons, found " + std::to_string(colonCount);
        return result;
    }
    
    size_t pos1 = report.find(':');
    if (pos1 == std::string::npos || pos1 == 0) {
        result.errorMessage = "Invalid TYPE field position";
        return result;
    }
    
    size_t pos2 = report.find(':', pos1 + 1);
    if (pos2 == std::string::npos) {
        result.errorMessage = "Invalid DETAILS field position";
        return result;
    }
    
    size_t pos3 = report.find(':', pos2 + 1);
    if (pos3 == std::string::npos) {
        result.errorMessage = "Invalid HWID field position";
        return result;
    }
    
    size_t pos4 = report.find(';', pos3 + 1);
    if (pos4 == std::string::npos || pos4 == pos3 + 1) {
        result.errorMessage = "Invalid SECRET field position";
        return result;
    }
    
    try {
        result.type = report.substr(0, pos1);
        result.details = report.substr(pos1 + 1, pos2 - pos1 - 1);
        result.hwid = report.substr(pos2 + 1, pos3 - pos2 - 1);
        result.secret = report.substr(pos3 + 1, pos4 - pos3 - 1);
    } catch (const std::out_of_range& e) {
        result.errorMessage = std::string("Parsing error: ") + e.what();
        return result;
    }
    
    if (result.type.length() > MAX_TYPE_LEN) {
        result.errorMessage = "TYPE field exceeds maximum length (" + std::to_string(MAX_TYPE_LEN) + ")";
        return result;
    }
    
    if (result.details.length() > MAX_DETAILS_LEN) {
        result.errorMessage = "DETAILS field exceeds maximum length (" + std::to_string(MAX_DETAILS_LEN) + ")";
        return result;
    }
    
    if (result.hwid.length() > MAX_HWID_LEN) {
        result.errorMessage = "HWID field exceeds maximum length (" + std::to_string(MAX_HWID_LEN) + ")";
        return result;
    }
    
    if (result.secret.length() > MAX_SECRET_LEN) {
        result.errorMessage = "SECRET field exceeds maximum length (" + std::to_string(MAX_SECRET_LEN) + ")";
        return result;
    }
    
    if (result.type.empty()) {
        result.errorMessage = "TYPE field cannot be empty";
        return result;
    }
    
    for (char c : result.type) {
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '_') {
            result.errorMessage = "TYPE field contains invalid characters";
            return result;
        }
    }
    
    if (result.hwid.empty()) {
        result.errorMessage = "HWID field cannot be empty";
        return result;
    }
    
    for (char c : result.hwid) {
        if (!std::isxdigit(static_cast<unsigned char>(c)) && c != '-') {
            result.errorMessage = "HWID field contains invalid characters (expected hex + dash)";
            return result;
        }
    }
    
    if (result.secret.empty()) {
        result.errorMessage = "SECRET field cannot be empty";
        return result;
    }
    
    result.details = SanitizeInput(result.details, MAX_DETAILS_LEN);
    
    result.valid = true;
    return result;
}

void HandleClient(SocketType clientSocket) {
    char buffer[BUFFER_LEN] = {0};
    ssize_t bytesReceived;
    std::string extractedHwid = "UNKNOWN";

    try {
        bytesReceived = recv(clientSocket, buffer, BUFFER_LEN - 1, 0);
        if (bytesReceived > 0) {
            buffer[bytesReceived] = '\0';
            
            std::string report(buffer, bytesReceived);
            extractedHwid = ExtractHWIDFromRawData(report);
            
            std::cout << "[DEBUG] Received raw data (" << bytesReceived << " bytes) from HWID: " << extractedHwid << std::endl;
            
            ParsedReport parsed = ParseProtocol(report);
            
            if (!parsed.valid) {
                std::cout << "[ERROR] Invalid protocol format: " << parsed.errorMessage << std::endl;
                std::cout << "[DEBUG] Expected format: TYPE:DETAILS:HWID:SECRET;" << std::endl;
                
                std::string truncatedReport = report.length() > 100 ? report.substr(0, 100) + "..." : report;
                LogViolation("MALFORMED_REQUEST", parsed.errorMessage + " | Data: " + truncatedReport, extractedHwid);
                
                const char* errorResponse = "ERROR:INVALID_FORMAT;";
                send(clientSocket, errorResponse, strlen(errorResponse), 0);
                closesocket_impl(clientSocket);
                return;
            }
            
            std::string type = parsed.type;
            std::string details = parsed.details;
            std::string hwid = parsed.hwid;
            std::string secret = parsed.secret;
            
            std::cout << "[PARSE] TYPE: " << type << " | HWID: " << hwid << " | DETAILS_LEN: " << details.length() << std::endl;

            if (secret != SERVER_SECRET) {
                std::cout << "[AUTH] Secret key tidak valid dari HWID [" << hwid << "]" << std::endl;
                std::cout << "[AUTH] Expected: " << SERVER_SECRET << " | Received: " << secret << std::endl;

                LogViolation("AUTH_FAILED", "Invalid secret key", hwid);

                const char* kickCommand = "KICK;";
                send(clientSocket, kickCommand, strlen(kickCommand), 0);
                std::cout << "[INFO] KICK dikirim (secret invalid). Review manual untuk ban jika diperlukan." << std::endl;
            }
            else if (type == "CHECKIN") {
                std::cout << "[CHECKIN] Client check-in dari HWID [" << hwid << "]" << std::endl;
                
                bool isBanned = IsHWIDBanned(hwid);
                
                if (isBanned) {
                    const char* kickCommand = "KICK;";
                    send(clientSocket, kickCommand, strlen(kickCommand), 0);
                    std::cout << "[BAN] HWID [" << hwid << "] terdeteksi di ban list. Perintah KICK dikirim." << std::endl;
                    std::cout << "[INFO] Untuk unban, hapus HWID dari bans.txt dan restart client." << std::endl;
                } else {
                    uint64_t sessionNonce = ((uint64_t)rand() << 32) ^ (uint64_t)rand();
                    std::string response = "OK;SESSION_NONCE:" + std::to_string(sessionNonce) + ";";
                    send(clientSocket, response.c_str(), response.length(), 0);
                    std::cout << "[OK] HWID [" << hwid << "] diizinkan. Memulai heartbeat ping." << std::endl;

                    Oblivion::HeartbeatConfig cfg; 
                    uint32_t seq = 1;
                    uint32_t consecutiveMiss = 0;
                    uint64_t rttSum = 0; uint32_t rttCount = 0; 
                    uint64_t rttSumCumulative = 0; uint64_t rttCountCumulative = 0; 
                    uint32_t totalMisses = 0;
                    enum class HbState { Healthy, Warning, Flagged } state = HbState::Healthy;

                    std::string sessionKey = hmacSha256(SERVER_SECRET, hwid + ":" + std::to_string(sessionNonce));
                    
                    std::cout << "[HEARTBEAT] Started for HWID [" << hwid << "]" << std::endl;

                    while (true) {
                        uint64_t ping_ts = GetTickCount64_impl();
                        uint64_t ping_nonce = ((uint64_t)rand() << 32) ^ (uint64_t)rand();
                        std::string ping = "PING:" + std::to_string(seq) + ":" + std::to_string(ping_ts) + ":" + std::to_string(ping_nonce) + ";";
                        ssize_t sres = send(clientSocket, ping.c_str(), ping.length(), 0);
                        if (sres <= 0) { 
                            std::cout << "[HEARTBEAT] Connection closed for HWID [" << hwid << "] - send failed" << std::endl; 
                            break; 
                        }

                        fd_set fdset;
                        FD_ZERO(&fdset);
                        FD_SET(clientSocket, &fdset);
                        struct timeval tv;
                        tv.tv_sec = (cfg.timeout_ms / 1000);
                        tv.tv_usec = (cfg.timeout_ms % 1000) * 1000;
                        int sel = select(clientSocket + 1, &fdset, NULL, NULL, &tv);
                        if (sel > 0) {
                            char rbuf[512] = {0};
                            ssize_t rcv = recv(clientSocket, rbuf, sizeof(rbuf) - 1, 0);
                            if (rcv > 0) {
                                std::string resp(rbuf, rcv);
                                size_t sc = resp.find(';');
                                if (sc != std::string::npos) resp = resp.substr(0, sc);
                                if (resp.rfind("PONG:", 0) == 0) {
                                    std::vector<size_t> col;
                                    size_t pos = 0;
                                    while ((pos = resp.find(':', pos)) != std::string::npos) {
                                        col.push_back(pos);
                                        pos++;
                                    }
                                    if (col.size() >= 6) {
                                        try {
                                            uint32_t pseq = std::stoul(resp.substr(col[0] + 1, col[1] - col[0] - 1));
                                            // tclient is parsed but not used (kept for protocol compatibility)
                                            (void)std::stoull(resp.substr(col[1] + 1, col[2] - col[1] - 1));
                                            uint64_t pnonce = std::stoull(resp.substr(col[2] + 1, col[3] - col[2] - 1));
                                            std::string status = resp.substr(col[3] + 1, col[4] - col[3] - 1);
                                            std::string phwid = resp.substr(col[4] + 1, col[5] - col[4] - 1);
                                            std::string hmac = resp.substr(col[5] + 1);

                                            if (pseq != seq || pnonce != ping_nonce) {
                                                std::cout << "[HB] seq/nonce mismatch - Expected seq=" << seq << " nonce=" << ping_nonce 
                                                          << " | Got seq=" << pseq << " nonce=" << pnonce << std::endl;
                                                consecutiveMiss++;
                                                totalMisses++;
                                            } else {
                                                std::string data = std::to_string(pseq) + ":" + std::to_string(ping_ts) + ":" + std::to_string(pnonce) + ":" + phwid;
                                                std::string expect = hmacSha256(sessionKey, data);
                                                if (expect != hmac) {
                                                    std::cout << "[HB] hmac mismatch" << std::endl;
                                                    consecutiveMiss++;
                                                    totalMisses++;
                                                } else {
                                                    uint64_t rtt = GetTickCount64_impl() - ping_ts;
                                                    rttSum += rtt; rttCount++;
                                                    rttSumCumulative += rtt; rttCountCumulative++;
                                                    consecutiveMiss = 0;
                                                    if (rttCount >= 5) {
                                                        uint64_t avg = rttSum / rttCount;
                                                        if (avg > cfg.rtt_warn_ms) {
                                                            if (state == HbState::Healthy) {
                                                                state = HbState::Warning;
                                                                std::cout << "[HB] state->WARNING (avg RTT=" << avg << ")" << std::endl;
                                                                double avgCumSnap = rttCountCumulative ? (double)rttSumCumulative / (double)rttCountCumulative : 0.0;
                                                                LogViolation("HB_WARNING", std::string("High average RTT ") + std::to_string(avg) +
                                                                    "ms | avgCum=" + std::to_string((int)avgCumSnap) + "ms | missesTotal=" + std::to_string(totalMisses), hwid);
                                                            }
                                                        } else if (state != HbState::Healthy) {
                                                            state = HbState::Healthy;
                                                            std::cout << "[HB] state->HEALTHY (avg RTT=" << avg << ")" << std::endl;
                                                        }
                                                        rttSum = 0; rttCount = 0;
                                                    }
                                                }
                                            }
                                        } catch (...) {
                                            std::cout << "[HB] parse error" << std::endl;
                                            consecutiveMiss++;
                                            totalMisses++;
                                        }
                                    } else {
                                        consecutiveMiss++;
                                        totalMisses++;
                                    }
                                } else {
                                    consecutiveMiss++;
                                    totalMisses++;
                                }
                            } else {
                                consecutiveMiss++;
                                totalMisses++;
                            }
                        } else {
                            consecutiveMiss++;
                            totalMisses++;
                        }

                        if (consecutiveMiss >= cfg.max_consecutive_miss) {
                            if (consecutiveMiss == 3) {
                                state = HbState::Warning;
                                double avgCumSnap = rttCountCumulative ? (double)rttSumCumulative / (double)rttCountCumulative : 0.0;
                                std::cout << "[HEARTBEAT] WARNING for HWID [" << hwid << "] - 3 consecutive misses | avgRTT=" << (int)avgCumSnap << "ms" << std::endl;
                                LogViolation("HB_WARNING", std::string("3 consecutive heartbeat misses | avgCum=") + std::to_string((int)avgCumSnap) +
                                    "ms | missesTotal=" + std::to_string(totalMisses), hwid);
                            } else if (consecutiveMiss >= 5) {
                                state = HbState::Flagged;
                                double avgCumSnap = rttCountCumulative ? (double)rttSumCumulative / (double)rttCountCumulative : 0.0;
                                std::cout << "[HEARTBEAT] FLAGGED for HWID [" << hwid << "] - Connection terminated (5+ misses) | avgRTT=" << (int)avgCumSnap << "ms" << std::endl;
                                LogViolation("HB_FLAGGED", std::string("5+ consecutive heartbeat misses | avgCum=") + std::to_string((int)avgCumSnap) +
                                    "ms | missesTotal=" + std::to_string(totalMisses), hwid);
                                break;
                            }
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
                    send(clientSocket, kickCommand, strlen(kickCommand), 0);
                    std::cout << "[INFO] Perintah KICK dikirim ke client (HWID: " << hwid << ") - sudah ada di ban list." << std::endl;
                } else {
                    std::cout << "[WARNING] Pelanggaran terdeteksi dari HWID [" << hwid << "], dicatat ke log (menunggu review manual)." << std::endl;
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

    auto readEnvUint = [](const char* name, uint32_t defVal) {
        const char* envVal = getenv(name);
        if (!envVal || !*envVal) return defVal;
        try {
            return (uint32_t)std::stoul(std::string(envVal));
        } catch (...) {
            return defVal;
        }
    };
    
    Oblivion::HeartbeatConfig globalHbCfg;
    globalHbCfg.interval_ms = readEnvUint("OBLV_HB_INTERVAL_MS", globalHbCfg.interval_ms);
    globalHbCfg.jitter_ms = readEnvUint("OBLV_HB_JITTER_MS", globalHbCfg.jitter_ms);
    globalHbCfg.timeout_ms = readEnvUint("OBLV_HB_TIMEOUT_MS", globalHbCfg.timeout_ms);
    globalHbCfg.max_consecutive_miss = readEnvUint("OBLV_HB_MAX_MISS", globalHbCfg.max_consecutive_miss);
    globalHbCfg.rtt_warn_ms = readEnvUint("OBLV_HB_RTT_WARN_MS", globalHbCfg.rtt_warn_ms);
    std::cout << "[HB CFG] interval=" << globalHbCfg.interval_ms << "ms jitter=" << globalHbCfg.jitter_ms
              << "ms timeout=" << globalHbCfg.timeout_ms << "ms maxMiss=" << globalHbCfg.max_consecutive_miss
              << " rttWarn=" << globalHbCfg.rtt_warn_ms << "ms" << std::endl;

    while (true) {
        ClientSocket = accept(ListenSocket, NULL, NULL);
        if (ClientSocket == INVALID_SOCKET_VAL) {
            std::cerr << "[ERROR] Accept gagal" << std::endl;
            continue;
        }

        std::cout << "\n[CONNECTION] New client connected" << std::endl;
        
        std::thread clientThread(HandleClient, ClientSocket);
        clientThread.detach();
    }

    closesocket_impl(ListenSocket);
#ifdef _WIN32
    WSACleanup();
#endif

    return 0;
}

