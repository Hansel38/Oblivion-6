#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>
#include <thread>
#include <vector>
#include <fstream>
#include <iterator>
#include <filesystem>
#include <cctype>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <algorithm>
#include <atomic>
#include <limits>
#include <cerrno>
#include <cstdlib>
#include <mutex>
#include <windows.h>
#include "secret_obf.h"
#include "include/heartbeat_protocol.h"
#include "include/socket_framing.h"
#include "include/protocol_validation.h"
#include "../common/network_configuration.h"
#include <bcrypt.h>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Bcrypt.lib")

// Fallback define for older SDKs where BCRYPT_ALG_HANDLE_HMAC is missing
#ifndef BCRYPT_ALG_HANDLE_HMAC
#define BCRYPT_ALG_HANDLE_HMAC 0x00000008
#endif

#define BUFFER_LEN 4096
#define MAX_TYPE_LEN 64
#define MAX_DETAILS_LEN 2048
#define MAX_HWID_LEN 128
// Ambil secret yang di-obfuscate agar tidak muncul sebagai literal.
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

bool ConstantTimeEquals(const std::string& left, const std::string& right) {
    if (left.size() != 64 || right.size() != 64) return false;
    unsigned char difference = 0;
    for (size_t i = 0; i < left.size(); ++i) {
        difference |= static_cast<unsigned char>(left[i] ^ right[i]);
    }
    return difference == 0;
}

static std::string HmacSha256(const std::string& key, const std::string& data) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    NTSTATUS status = BCryptOpenAlgorithmProvider(
        &hAlg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC);
    if (status != 0) return std::string();

    DWORD objectLength = 0;
    DWORD resultLength = 0;
    status = BCryptGetProperty(
        hAlg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objectLength),
        sizeof(objectLength), &resultLength, 0);
    if (status != 0 || objectLength == 0 ||
        key.size() > (std::numeric_limits<ULONG>::max)() ||
        data.size() > (std::numeric_limits<ULONG>::max)()) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return std::string();
    }

    std::vector<UCHAR> hashObject(objectLength);
    status = BCryptCreateHash(
        hAlg, &hHash, hashObject.data(), objectLength,
        reinterpret_cast<PUCHAR>(const_cast<char*>(key.data())),
        static_cast<ULONG>(key.size()), 0);
    if (status == 0) {
        status = BCryptHashData(
            hHash, reinterpret_cast<PUCHAR>(const_cast<char*>(data.data())),
            static_cast<ULONG>(data.size()), 0);
    }

    UCHAR digest[32]{};
    if (status == 0) {
        status = BCryptFinishHash(hHash, digest, sizeof(digest), 0);
    }
    if (hHash) BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    if (status != 0) return std::string();

    static const char* hex = "0123456789abcdef";
    std::string output;
    output.reserve(64);
    for (unsigned char value : digest) {
        output.push_back(hex[(value >> 4) & 0x0F]);
        output.push_back(hex[value & 0x0F]);
    }
    return output;
}

static std::string BuildRequestAuthData(
    const std::string& type, const std::string& details,
    const std::string& hwid, const std::string& challengeNonce) {
    return "REQUEST:" + type + ":" + std::to_string(details.size()) + ":" +
           details + ":" + hwid + ":" + challengeNonce;
}

static bool ParseHelloFrame(const std::string& frame, std::string& hwid) {
    static const std::string prefix = "HELLO:";
    hwid.clear();
    if (frame.rfind(prefix, 0) != 0 || frame.size() <= prefix.size() ||
        frame.back() != ';' ||
        frame.find(':', prefix.size()) != std::string::npos) {
        return false;
    }

    hwid = frame.substr(prefix.size(), frame.size() - prefix.size() - 1);
    if (hwid.empty() || hwid.size() > MAX_HWID_LEN) return false;
    for (unsigned char c : hwid) {
        if (!std::isxdigit(c) && c != '-') return false;
    }
    return true;
}



// Fungsi untuk mendapatkan path folder tempat executable berada
std::string GetExecutableDirectory() {
#ifdef _WIN32
    size_t capacity = 512;
    while (capacity <= 32768) {
        std::vector<char> exePath(capacity, '\0');
        const DWORD length = GetModuleFileNameA(
            NULL, exePath.data(), static_cast<DWORD>(exePath.size()));
        if (length == 0) return "";
        if (length < exePath.size() - 1) {
            const std::string path(exePath.data(), length);
            const size_t lastSlash = path.find_last_of("\\/");
            return lastSlash == std::string::npos
                ? std::string()
                : path.substr(0, lastSlash + 1);
        }
        capacity *= 2;
    }
    return "";
#else
    size_t capacity = 512;
    while (capacity <= 32768) {
        std::vector<char> exePath(capacity);
        const ssize_t length = readlink(
            "/proc/self/exe", exePath.data(), exePath.size());
        if (length < 0) return "";
        if (static_cast<size_t>(length) < exePath.size()) {
            const std::string path(exePath.data(), static_cast<size_t>(length));
            const size_t lastSlash = path.find_last_of('/');
            return lastSlash == std::string::npos
                ? std::string()
                : path.substr(0, lastSlash + 1);
        }
        capacity *= 2;
    }
    return "";
#endif
}
// Fungsi untuk mendapatkan path lengkap file (relatif terhadap executable)
std::string GetFilePath(const std::string& filename) {
    const std::string exeDir = GetExecutableDirectory();
    return exeDir.empty() ? std::string() : exeDir + filename;
}

// Fungsi helper untuk mendapatkan timestamp saat ini
std::string GetCurrentTimestamp() {
    auto now = std::time(nullptr);
    struct tm tm;
    localtime_s(&tm, &now);
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

// Fungsi untuk mengecek apakah HWID sudah di-ban
// PENTING: File bans.txt dibaca fresh setiap kali fungsi ini dipanggil (tidak ada caching)
// Untuk unban HWID, cukup hapus baris HWID dari bans.txt dan restart client
enum class BanListStatus {
    NotBanned,
    Banned,
    Unavailable
};

static std::mutex g_banListMutex;

class BanListFileLock {
public:
    BanListFileLock(const std::string& banFilePath, bool exclusive) {
        const std::string lockPath = banFilePath + ".lock";
        m_handle = CreateFileA(
            lockPath.c_str(), GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (m_handle == INVALID_HANDLE_VALUE) return;

        const DWORD flags = exclusive ? LOCKFILE_EXCLUSIVE_LOCK : 0;
        m_locked = LockFileEx(
            m_handle, flags, 0, MAXDWORD, MAXDWORD, &m_overlapped) != FALSE;
        if (!m_locked) {
            CloseHandle(m_handle);
            m_handle = INVALID_HANDLE_VALUE;
        }
    }

    ~BanListFileLock() {
        if (m_locked) {
            UnlockFileEx(m_handle, 0, MAXDWORD, MAXDWORD, &m_overlapped);
        }
        if (m_handle != INVALID_HANDLE_VALUE) CloseHandle(m_handle);
    }

    BanListFileLock(const BanListFileLock&) = delete;
    BanListFileLock& operator=(const BanListFileLock&) = delete;
    explicit operator bool() const { return m_locked; }

private:
    HANDLE m_handle = INVALID_HANDLE_VALUE;
    OVERLAPPED m_overlapped{};
    bool m_locked = false;
};

static bool AppendBanListEntryAtomically(
    const std::string& banFilePath, const std::string& hwid) {
    std::string currentContents;
    std::error_code filesystemError;
    const bool fileExists = std::filesystem::exists(banFilePath, filesystemError);
    if (filesystemError) return false;

    if (fileExists) {
        std::ifstream input(banFilePath, std::ios::binary);
        if (!input.is_open()) return false;
        currentContents.assign(
            std::istreambuf_iterator<char>(input),
            std::istreambuf_iterator<char>());
        if (input.bad()) return false;
    }

    if (!currentContents.empty() && currentContents.back() != '\n') {
        currentContents.push_back('\n');
    }
    currentContents += hwid;
    currentContents.push_back('\n');

    std::string temporaryPath;
    HANDLE temporaryFile = INVALID_HANDLE_VALUE;
    for (unsigned int attempt = 0; attempt < 16; ++attempt) {
        temporaryPath = banFilePath + ".tmp." +
            std::to_string(GetCurrentProcessId()) + "." +
            std::to_string(GetTickCount64()) + "." + std::to_string(attempt);
        temporaryFile = CreateFileA(
            temporaryPath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL, nullptr);
        if (temporaryFile != INVALID_HANDLE_VALUE) break;
        const DWORD error = GetLastError();
        if (error != ERROR_FILE_EXISTS && error != ERROR_ALREADY_EXISTS) return false;
    }
    if (temporaryFile == INVALID_HANDLE_VALUE) return false;

    bool writeSucceeded = true;
    size_t totalWritten = 0;
    while (totalWritten < currentContents.size()) {
        const size_t remaining = currentContents.size() - totalWritten;
        const DWORD request = static_cast<DWORD>((std::min)(
            remaining, static_cast<size_t>((std::numeric_limits<DWORD>::max)())));
        DWORD written = 0;
        if (!WriteFile(temporaryFile, currentContents.data() + totalWritten,
                       request, &written, nullptr) || written == 0) {
            writeSucceeded = false;
            break;
        }
        totalWritten += static_cast<size_t>(written);
    }
    if (writeSucceeded && !FlushFileBuffers(temporaryFile)) writeSucceeded = false;
    CloseHandle(temporaryFile);
    if (!writeSucceeded) {
        DeleteFileA(temporaryPath.c_str());
        return false;
    }

    const DWORD attributes = GetFileAttributesA(banFilePath.c_str());
    bool replaced = false;
    if (attributes != INVALID_FILE_ATTRIBUTES) {
        replaced = ReplaceFileA(
            banFilePath.c_str(), temporaryPath.c_str(), nullptr,
            0, nullptr, nullptr) != FALSE;
    } else {
        const DWORD error = GetLastError();
        if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) {
            replaced = MoveFileExA(
                temporaryPath.c_str(), banFilePath.c_str(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != FALSE;
        }
    }

    if (!replaced) DeleteFileA(temporaryPath.c_str());
    return replaced;
}

static bool IsSameBanListHwid(
    const std::string& left, const std::string& right) {
    if (left.size() != right.size()) return false;
    for (size_t i = 0; i < left.size(); ++i) {
        unsigned char a = static_cast<unsigned char>(left[i]);
        unsigned char b = static_cast<unsigned char>(right[i]);
        if (a >= 'A' && a <= 'F') a = static_cast<unsigned char>(a + ('a' - 'A'));
        if (b >= 'A' && b <= 'F') b = static_cast<unsigned char>(b + ('a' - 'A'));
        if (a != b) return false;
    }
    return true;
}

static bool IsValidBanListHwid(const std::string& hwid) {
    if (hwid.size() != 64) return false;
    for (unsigned char value : hwid) {
        if (!((value >= '0' && value <= '9') ||
              (value >= 'a' && value <= 'f') ||
              (value >= 'A' && value <= 'F'))) {
            return false;
        }
    }
    return true;
}

// Caller must hold g_banListMutex and the sidecar BanListFileLock.
static BanListStatus CheckHWIDBanStatusUnlocked(const std::string& hwid) {
    if (!IsValidBanListHwid(hwid)) {
        return BanListStatus::Unavailable;
    }

    const std::string banFilePath = GetFilePath(BAN_LIST_FILE);
    if (banFilePath.empty()) return BanListStatus::Unavailable;

    std::error_code filesystemError;
    const bool fileExists = std::filesystem::exists(banFilePath, filesystemError);
    if (filesystemError) return BanListStatus::Unavailable;
    if (!fileExists) return BanListStatus::NotBanned;

    std::ifstream banFile(banFilePath);
    if (!banFile.is_open()) return BanListStatus::Unavailable;

    bool matched = false;
    std::string line;
    while (std::getline(banFile, line)) {
        const size_t firstNonWhitespace = line.find_first_not_of(" \t\n\r");
        if (firstNonWhitespace == std::string::npos) continue;

        const size_t lastNonWhitespace = line.find_last_not_of(" \t\n\r");
        line = line.substr(firstNonWhitespace, lastNonWhitespace - firstNonWhitespace + 1);
        if (line.empty() || line[0] == '#') continue;

        // A malformed active entry makes the list unreliable. Never treat
        // a partially valid list as proof that this HWID is not banned.
        if (!IsValidBanListHwid(line)) return BanListStatus::Unavailable;

        if (IsSameBanListHwid(line, hwid)) {
            matched = true;
        }
    }

    if (banFile.bad() || (banFile.fail() && !banFile.eof())) {
        return BanListStatus::Unavailable;
    }
    return matched ? BanListStatus::Banned : BanListStatus::NotBanned;
}

static BanListStatus CheckHWIDBanStatus(const std::string& hwid) {
    std::lock_guard<std::mutex> lock(g_banListMutex);
    const std::string banFilePath = GetFilePath(BAN_LIST_FILE);
    if (banFilePath.empty()) return BanListStatus::Unavailable;
    BanListFileLock fileLock(banFilePath, false);
    if (!fileLock) return BanListStatus::Unavailable;
    return CheckHWIDBanStatusUnlocked(hwid);
}

// Checks and updates use the same OS-level lock, including across server processes.
void AddToBanList(const std::string& hwid) {
    if (!IsValidBanListHwid(hwid)) {
        std::cerr << "[ERROR] Menolak HWID tidak valid untuk ban list." << std::endl;
        return;
    }

    std::lock_guard<std::mutex> lock(g_banListMutex);
    const std::string banFilePath = GetFilePath(BAN_LIST_FILE);
    if (banFilePath.empty()) {
        std::cerr << "[ERROR] Path ban list tidak tersedia." << std::endl;
        return;
    }

    BanListFileLock fileLock(banFilePath, true);
    if (!fileLock) {
        std::cerr << "[ERROR] Gagal memperoleh lock lintas proses untuk ban list." << std::endl;
        return;
    }

    const BanListStatus status = CheckHWIDBanStatusUnlocked(hwid);
    if (status == BanListStatus::Banned) return;
    if (status == BanListStatus::Unavailable) {
        std::cerr << "[ERROR] Ban list tidak dapat dibaca atau berisi entri tidak valid; penulisan dibatalkan." << std::endl;
        return;
    }

    if (!AppendBanListEntryAtomically(banFilePath, hwid)) {
        std::cerr << "[ERROR] Gagal memperbarui ban list secara atomik." << std::endl;
        return;
    }

    std::cout << "[BAN] HWID [" << hwid << "] ditambahkan ke ban list." << std::endl;
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

// Fungsi untuk mencatat pelanggaran ke log file
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

// Fungsi untuk menentukan apakah pelanggaran serius dan perlu di-ban
bool IsSeriousViolation(const std::string& type) {
    // Daftar tipe pelanggaran yang dianggap serius dan langsung di-ban
    std::vector<std::string> seriousViolations = {
        "MEMORY_VIOLATION",
        "INJECTION_DETECTED",
        "FILE_MODIFIED",
        "FILE_INTEGRITY_FAILED",
        "SIGNATURE_SPOOFING",      // Spoofing process name dengan fake signature
        "ADV_HEURISTIC_DETECTED",  // Advanced heuristics detection (CE, WPE, dll)
        "PROCESS_DETECTED"         // Blacklisted process detected
    };
    
    for (const auto& serious : seriousViolations) {
        if (_stricmp(type.c_str(), serious.c_str()) == 0) {
            return true;
        }
    }
    
    return false;
}

// Fungsi untuk mencoba extract HWID dari raw data (best effort)
std::string ExtractHWIDFromRawData(const std::string& rawData) {
    // Format yang diharapkan: TYPE:DETAILS:HWID:CHALLENGE_NONCE:MAC;
    // Kita akan coba extract HWID bahkan jika format tidak sempurna
    
    size_t firstColon = rawData.find(':');
    if (firstColon == std::string::npos) return "UNKNOWN";
    
    size_t secondColon = rawData.find(':', firstColon + 1);
    if (secondColon == std::string::npos) return "UNKNOWN";
    
    size_t thirdColon = rawData.find(':', secondColon + 1);
    if (thirdColon == std::string::npos) return "UNKNOWN";
    
    // Extract HWID (antara colon ke-2 dan ke-3)
    std::string hwid = rawData.substr(secondColon + 1, thirdColon - secondColon - 1);
    
    // Validasi panjang minimal dan maksimal
    if (hwid.empty() || hwid.length() > MAX_HWID_LEN) return "UNKNOWN";
    
    // Sanitasi: hanya izinkan alphanumeric dan dash (untuk SHA256 hash: 0-9a-f dan dash)
    // Tidak perlu filter ketat, cukup buang karakter berbahaya
    std::string sanitizedHwid;
    for (char c : hwid) {
        // Izinkan: alphanumeric (0-9, a-z, A-Z) dan dash
        if (std::isalnum(static_cast<unsigned char>(c)) || c == '-') {
            sanitizedHwid += c;
        }
    }
    
    return sanitizedHwid.empty() ? "UNKNOWN" : sanitizedHwid;
}

// Fungsi untuk sanitasi string input (menghapus karakter berbahaya)
std::string SanitizeInput(const std::string& input, size_t maxLen) {
    std::string sanitized;
    size_t reserveSize = input.length() < maxLen ? input.length() : maxLen;
    sanitized.reserve(reserveSize);
    
    for (size_t i = 0; i < input.length() && sanitized.length() < maxLen; i++) {
        char c = input[i];
        // Hanya izinkan karakter printable ASCII dan beberapa karakter khusus yang aman
        // Strip CR/LF/TAB so untrusted reports cannot forge log lines.
        if (c >= 0x20 && c <= 0x7E) {
            // Filter karakter yang bisa digunakan untuk injection
            if (c != '<' && c != '>' && c != '&' && c != '"' && c != '\'') {
                sanitized += c;
            }
        }
    }
    
    return sanitized;
}

// Struktur untuk hasil parsing protokol
struct ParsedReport {
    bool valid = false;
    std::string type;
    std::string details;
    std::string hwid;
    std::string challengeNonce;
    std::string mac;
    std::string errorMessage;
};

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
        !OblivionNet::IsValidChallengeNonce(result.challengeNonce) ||
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


// Fungsi untuk menangani setiap client yang terhubung
void HandleClient(SOCKET clientSocket, Oblivion::HeartbeatConfig sessionHeartbeatConfig) {
    const uint32_t activeBefore = g_activeClientCount.fetch_add(1, std::memory_order_relaxed);
    if (activeBefore >= kMaxConcurrentClients) {
        g_activeClientCount.fetch_sub(1, std::memory_order_relaxed);
        const char* busyResponse = "BUSY;";
        OblivionNet::SendAll(clientSocket, busyResponse, strlen(busyResponse));
        closesocket(clientSocket);
        return;
    }
    ActiveClientGuard activeGuard{ g_activeClientCount };
    int bytesReceived = 0;
    std::string extractedHwid = "UNKNOWN"; // Untuk logging jika parsing gagal
    std::string pendingNetworkData;
    std::string report;

    try {
        if (!OblivionNet::ReceiveFrame(clientSocket, pendingNetworkData,
                                       report, 5000, BUFFER_LEN - 1)) {
            LogViolation("FRAME_READ_FAILED", "Timed out or received an oversized/incomplete HELLO request", extractedHwid);
            closesocket(clientSocket);
            return;
        }

        std::string helloHwid;
        if (!ParseHelloFrame(report, helloHwid) || !pendingNetworkData.empty()) {
            LogViolation("MALFORMED_REQUEST", "Expected one HELLO:<HWID>; frame", extractedHwid);
            closesocket(clientSocket);
            return;
        }
        extractedHwid = helloHwid;

        uint64_t challengeNonceValue = 0;
        if (!OblivionNet::GenerateSecureNonce(challengeNonceValue)) {
            LogViolation("RNG_FAILURE", "Unable to generate request challenge nonce", helloHwid);
            closesocket(clientSocket);
            return;
        }
        const std::string challengeNonce = std::to_string(challengeNonceValue);
        const std::string challengeMac =
            HmacSha256(
                SERVER_SECRET, "CHALLENGE:" + helloHwid + ":" + challengeNonce);
        if (challengeMac.size() != 64) {
            LogViolation("AUTH_CRYPTO_FAILURE", "Unable to authenticate request challenge", helloHwid);
            closesocket(clientSocket);
            return;
        }
        const std::string challengeResponse =
            "CHALLENGE:" + challengeNonce + ":" + challengeMac + ";";
        if (!OblivionNet::SendAll(clientSocket, challengeResponse.data(), challengeResponse.size())) {
            closesocket(clientSocket);
            return;
        }

        report.clear();
        pendingNetworkData.clear();
        if (!OblivionNet::ReceiveFrame(clientSocket, pendingNetworkData,
                                       report, 5000, BUFFER_LEN - 1)) {
            LogViolation("FRAME_READ_FAILED", "Timed out or received an incomplete authenticated request", helloHwid);
            closesocket(clientSocket);
            return;
        }
        if (!pendingNetworkData.empty()) {
            LogViolation("MALFORMED_REQUEST", "Unexpected bytes after authenticated request frame", helloHwid);
            closesocket(clientSocket);
            return;
        }

        bytesReceived = static_cast<int>(report.size());
        if (bytesReceived > 0) {
            std::cout << "[DEBUG] Received authenticated request (" << bytesReceived
                      << " bytes) from HWID: " << extractedHwid << std::endl;

            ParsedReport parsed = ParseProtocol(report);
            
            if (!parsed.valid) {
                std::cout << "[ERROR] Invalid protocol format: " << parsed.errorMessage << std::endl;
                std::cout << "[DEBUG] Expected format: TYPE:DETAILS:HWID:NONCE:MAC;" << std::endl;
                
                // Log attempt dengan data mentah (truncated untuk keamanan)
                // Never log raw untrusted protocol bytes; they may contain control characters.
                LogViolation("MALFORMED_REQUEST", parsed.errorMessage, extractedHwid);
                
                // Kirim error response dan tutup koneksi
                const char* errorResponse = "ERROR:INVALID_FORMAT;";
                OblivionNet::SendAll(clientSocket, errorResponse, strlen(errorResponse));
                closesocket(clientSocket);
                return;
            }
            
            const std::string type = parsed.type;
            const std::string details = SanitizeInput(parsed.details, MAX_DETAILS_LEN);
            const std::string hwid = parsed.hwid;
            const std::string expectedRequestMac = HmacSha256(
                SERVER_SECRET,
                BuildRequestAuthData(type, parsed.details, hwid, challengeNonce));
            const bool requestAuthenticated =
                hwid == helloHwid && parsed.challengeNonce == challengeNonce &&
                ConstantTimeEquals(expectedRequestMac, parsed.mac);

            std::cout << "[PARSE] TYPE: " << type << " | HWID: " << hwid
                      << " | DETAILS_LEN: " << details.length() << std::endl;

            if (!requestAuthenticated) {
                LogViolation("AUTH_FAILED", "Invalid challenge-response MAC", hwid);
                const char* authError = "ERROR:AUTH_FAILED;";
                OblivionNet::SendAll(clientSocket, authError, strlen(authError));
                closesocket(clientSocket);
                return;
            }
            else if (type == "CHECKIN") {
                // Ini adalah check-in dari client saat pertama kali start
                std::cout << "[CHECKIN] Client check-in dari HWID [" << hwid << "]" << std::endl;
                
                // Cek apakah HWID sudah di-ban (file dibaca fresh setiap kali, tidak ada cache)
                const BanListStatus banStatus = CheckHWIDBanStatus(hwid);
                if (banStatus == BanListStatus::Unavailable) {
                    LogViolation("BAN_LIST_UNAVAILABLE", "Ban list could not be read or contains malformed entries", hwid);
                    closesocket(clientSocket);
                    return;
                }
                const bool isBanned = banStatus == BanListStatus::Banned;
                
                if (isBanned) {
                    // HWID di-ban, kirim KICK
                    const std::string kickMac = HmacSha256(
                        SERVER_SECRET, "RESPONSE:KICK:" + hwid + ":" + challengeNonce);
                    if (kickMac.size() != 64) {
                        LogViolation("AUTH_CRYPTO_FAILURE", "Unable to authenticate ban response", hwid);
                        closesocket(clientSocket);
                        return;
                    }
                    const std::string kickCommand = "KICK:" + kickMac + ";";
                    OblivionNet::SendAll(clientSocket, kickCommand.data(), kickCommand.size());
                    std::cout << "[BAN] HWID [" << hwid << "] terdeteksi di ban list. Perintah KICK dikirim." << std::endl;
                    std::cout << "[INFO] Untuk unban, hapus HWID dari bans.txt dan restart client." << std::endl;
                } else {
                    // Negotiate the exact heartbeat timing used by this server session.
                    const Oblivion::HeartbeatConfig& cfg = sessionHeartbeatConfig;
                    uint64_t sessionNonce = 0;
                    if (!OblivionNet::GenerateSecureNonce(sessionNonce)) {
                        LogViolation("RNG_FAILURE", "Unable to generate secure session nonce", hwid);
                        closesocket(clientSocket);
                        return;
                    }
                    const std::string sessionNonceText = std::to_string(sessionNonce);
                    const std::string sessionAuthData =
                        "SESSION:" + hwid + ":" + challengeNonce + ":" + sessionNonceText + ":" +
                        std::to_string(cfg.interval_ms) + ":" + std::to_string(cfg.timeout_ms);
                    const std::string sessionAuthMac = HmacSha256(SERVER_SECRET, sessionAuthData);
                    if (sessionAuthMac.size() != 64) {
                        LogViolation("AUTH_CRYPTO_FAILURE", "Unable to authenticate session configuration", hwid);
                        closesocket(clientSocket);
                        return;
                    }
                    const std::string statusMac = HmacSha256(
                        SERVER_SECRET, "RESPONSE:OK:" + hwid + ":" + challengeNonce);
                    if (statusMac.size() != 64) {
                        LogViolation("AUTH_CRYPTO_FAILURE", "Unable to authenticate check-in response", hwid);
                        closesocket(clientSocket);
                        return;
                    }
                    std::string response = "OK:" + statusMac + ";SESSION_NONCE:" + sessionNonceText +
                                           ";HB_CONFIG:" + std::to_string(cfg.interval_ms) +
                                           ":" + std::to_string(cfg.timeout_ms) +
                                           ";SESSION_AUTH:" + sessionAuthMac + ";";
                    if (!OblivionNet::SendAll(clientSocket, response.data(), response.size())) {
                        closesocket(clientSocket);
                        return;
                    }
                    std::cout << "[OK] HWID [" << hwid << "] diizinkan. Memulai heartbeat ping." << std::endl;

                    // Basic ping scheduler over the same socket (line-based)
                    uint32_t seq = 1;
                    uint32_t consecutiveMiss = 0;
                    std::string lastClientStatus;
                    uint64_t rttSum = 0; uint32_t rttCount = 0; 
                    // Cumulative metrics across the connection
                    uint64_t rttSumCumulative = 0; uint64_t rttCountCumulative = 0; 
                    uint32_t totalMisses = 0;
                    enum class HbState { Healthy, Warning, Flagged } state = HbState::Healthy;

                    // derive session key: key' = HMAC_SHA256(SERVER_SECRET, hwid|nonce)
                    auto hmacSha256 = [](const std::string& key, const std::string& data){
                        BCRYPT_ALG_HANDLE hAlg = NULL; BCRYPT_HASH_HANDLE hHash = NULL;
                        NTSTATUS st = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC);
                        if (st != 0) return std::string(); DWORD objLen=0, dlen=0;
                        st = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objLen, sizeof(DWORD), &dlen, 0);
                        if (st != 0 || objLen == 0) {
                            BCryptCloseAlgorithmProvider(hAlg, 0);
                            return std::string();
                        }
                        std::vector<UCHAR> obj(objLen);
                        st = BCryptCreateHash(hAlg, &hHash, obj.data(), objLen, (PUCHAR)key.data(), (ULONG)key.size(), 0);
                        if (st != 0) { BCryptCloseAlgorithmProvider(hAlg,0); return std::string(); }
                        st = BCryptHashData(hHash, (PUCHAR)data.data(), (ULONG)data.size(), 0);
                        if (st != 0) { BCryptDestroyHash(hHash); BCryptCloseAlgorithmProvider(hAlg,0); return std::string(); }
                        UCHAR hash[32]; st = BCryptFinishHash(hHash, hash, sizeof(hash), 0);
                        BCryptDestroyHash(hHash); BCryptCloseAlgorithmProvider(hAlg,0);
                        if (st != 0) return std::string(); static const char* hex = "0123456789abcdef";
                        std::string out; out.reserve(64); for(int i=0;i<32;++i){ out.push_back(hex[(hash[i]>>4)&0xF]); out.push_back(hex[hash[i]&0xF]); }
                        return out;
                    };
                    std::string sessionKey = hmacSha256(SERVER_SECRET, "SESSION_KEY:v1:" + hwid + ":" +
                        challengeNonce + ":" + std::to_string(sessionNonce));
                    if (sessionKey.size() != 64) {
                        LogViolation("HB_CRYPTO_FAILURE", "Unable to derive heartbeat session key", hwid);
                        closesocket(clientSocket);
                        return;
                    }
                    
                    std::cout << "[HEARTBEAT] Started for HWID [" << hwid << "]" << std::endl;

                    while (true) {
                        // Authenticate each server PING with the active session key.
                        uint64_t ping_ts = (uint64_t)GetTickCount64();
                        // naive nonce
                        uint64_t ping_nonce = 0;
                        if (!OblivionNet::GenerateSecureNonce(ping_nonce)) {
                            LogViolation("RNG_FAILURE", "Unable to generate secure heartbeat nonce", hwid);
                            break;
                        }
                        const std::string pingAuthData =
                            "PING:" + std::to_string(seq) + ":" + std::to_string(ping_ts) + ":" +
                            std::to_string(ping_nonce) + ":" + hwid;
                        const std::string pingMac = hmacSha256(sessionKey, pingAuthData);
                        if (pingMac.size() != 64) {
                            LogViolation("HB_CRYPTO_FAILURE", "Unable to authenticate heartbeat ping", hwid);
                            break;
                        }
                        const std::string ping = pingAuthData + ":" + pingMac + ";";
                        const bool pingSent = OblivionNet::SendAll(clientSocket, ping.data(), ping.size());
                        if (!pingSent) { 
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
                                        size_t parsedSeq = 0, parsedClientTs = 0, parsedNonce = 0;
                                        const unsigned long seqValue = std::stoul(
                                            resp.substr(col[0] + 1, col[1] - col[0] - 1), &parsedSeq);
                                        const std::string seqText = resp.substr(col[0] + 1, col[1] - col[0] - 1);
                                        const std::string clientTsText = resp.substr(col[1] + 1, col[2] - col[1] - 1);
                                        const std::string nonceText = resp.substr(col[2] + 1, col[3] - col[2] - 1);
                                        const uint64_t pnonce = std::stoull(nonceText, &parsedNonce);
                                        const uint64_t tclient = std::stoull(clientTsText, &parsedClientTs);
                                        (void)tclient;
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

                                        const bool statusWellFormed =
                                            Oblivion::IsValidClientStatus(status);

                                        if (!Oblivion::IsExpectedHeartbeatSequence(pseq, seq) ||
                                            pnonce != ping_nonce || phwid != hwid ||
                                            !statusWellFormed) {
                                            ++consecutiveMiss;
                                            ++totalMisses;
                                        } else {
                                            const std::string data =
                                                Oblivion::BuildPongAuthData(
                                                    pseq, clientTsText, pnonce, status, phwid);
                                            const std::string expect = hmacSha256(sessionKey, data);
                                            if (!ConstantTimeEquals(expect, hmac)) {
                                                ++consecutiveMiss;
                                                ++totalMisses;
                                            } else {
                                                if (status != lastClientStatus) {
                                                    const std::string healthDetails =
                                                        "antiSuspendOk=" + status.substr(0, 1) +
                                                        "; integrityOk=" + status.substr(2, 1);
                                                    if (status == "1|1") {
                                                        if (!lastClientStatus.empty()) {
                                                            LogViolation("HB_CLIENT_HEALTH_RESTORED",
                                                                healthDetails, hwid);
                                                        }
                                                    } else {
                                                        LogViolation("HB_CLIENT_HEALTH_UNAVAILABLE",
                                                            healthDetails, hwid);
                                                    }
                                                    lastClientStatus = status;
                                                }

                                                const uint64_t rtt = static_cast<uint64_t>(GetTickCount64()) - ping_ts;
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

                        // Check consecutive miss threshold
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
                        Sleep(cfg.interval_ms);
                    }
                }
            } else {
                // Handler untuk violation reports lainnya
                std::cout << "[INFO] Laporan diterima dari HWID [" << hwid << "]: " << type << " - " << details << std::endl;
                
                // --- LOGIKA SERVER: CEK BAN LIST DAN LOG PELANGGARAN ---
                
                // 1. Catat semua pelanggaran ke log file
                LogViolation(type, details, hwid);
                
                // 2. Cek apakah HWID sudah di-ban (hanya cek, tidak auto-ban)
                const BanListStatus banStatus = CheckHWIDBanStatus(hwid);
                if (banStatus == BanListStatus::Unavailable) {
                    LogViolation("BAN_LIST_UNAVAILABLE", "Ban list could not be read or contains malformed entries", hwid);
                    closesocket(clientSocket);
                    return;
                }
                const bool isBanned = banStatus == BanListStatus::Banned;
                
                // 3. AUTO-BAN DISABLED - Admin melakukan ban manual via bans.txt
                // bool isSerious = IsSeriousViolation(type);
                // if (isSerious && !isBanned) {
                //     AddToBanList(hwid);
                //     isBanned = true;
                //     std::cout << "[BAN] Pelanggaran serius terdeteksi! HWID [" << hwid << "] di-ban otomatis." << std::endl;
                // }
                
                // 4. Kirim perintah KICK hanya jika sudah di-ban secara manual
                const std::string responseStatus = isBanned ? "KICK" : "OK";
                const std::string responseMac = HmacSha256(
                    SERVER_SECRET, "RESPONSE:" + responseStatus + ":" + hwid + ":" + challengeNonce);
                if (responseMac.size() != 64) {
                    LogViolation("AUTH_CRYPTO_FAILURE", "Unable to authenticate report acknowledgement", hwid);
                    closesocket(clientSocket);
                    return;
                }
                const std::string responseFrame = responseStatus + ":" + responseMac + ";";
                OblivionNet::SendAll(clientSocket, responseFrame.data(), responseFrame.size());
                if (isBanned) {
                    std::cout << "[INFO] Perintah KICK dikirim ke client (HWID: " << hwid << ") - sudah ada di ban list." << std::endl;
                } else {
                    std::cout << "[WARNING] Pelanggaran terdeteksi dari HWID [" << hwid
                              << "], dicatat ke log (menunggu review manual)." << std::endl;
                }
            }
        } else if (bytesReceived == 0) {
            std::cout << "[INFO] Client closed connection gracefully" << std::endl;
        } else {
            int errorCode = WSAGetLastError();
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

    closesocket(clientSocket);
}

int main() {
    if (SERVER_SECRET.size() < 32) {
        std::cerr << "[FATAL] OBLIVION_SECRET must contain at least 32 bytes; refusing to start." << std::endl;
        return 1;
    }

    WSADATA wsaData;
    int iResult;

    SOCKET ListenSocket = INVALID_SOCKET;
    SOCKET ClientSocket = INVALID_SOCKET;

    struct addrinfo* result = NULL;
    struct addrinfo hints;

    // Inisialisasi Winsock
    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        std::cerr << "WSAStartup gagal dengan error: " << iResult << std::endl;
        return 1;
    }

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET; // IPv4
    hints.ai_socktype = SOCK_STREAM; // TCP
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE; // Untuk bind()

    // Resolve alamat server dan port. Use the MSVC-safe environment API.
    char* configuredPortValue = nullptr;
    size_t configuredPortLength = 0;
    const errno_t environmentResult =
        _dupenv_s(&configuredPortValue, &configuredPortLength, "OBLIVION_LISTEN_PORT");
    std::string configuredPort;
    if (environmentResult == 0 && configuredPortValue != nullptr &&
        configuredPortLength > 0) {
        configuredPort.assign(configuredPortValue, configuredPortLength - 1);
    }
    std::free(configuredPortValue);

    uint16_t listenPort = 0;
    if (configuredPort.empty() ||
        !OblivionNet::ParseTcpPort(configuredPort, listenPort)) {
        std::cerr << "[ERROR] OBLIVION_LISTEN_PORT must be configured with a TCP port from 1 through 65535." << std::endl;
        WSACleanup();
        return 1;
    }
    const std::string listenPortText = OblivionNet::FormatTcpPort(listenPort);

    iResult = getaddrinfo(NULL, listenPortText.c_str(), &hints, &result);
    if (iResult != 0) {
        std::cerr << "getaddrinfo gagal dengan error: " << iResult << std::endl;
        WSACleanup();
        return 1;
    }

    // Buat socket untuk mendengarkan koneksi client
    ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (ListenSocket == INVALID_SOCKET) {
        std::cerr << "Socket gagal dibuat dengan error: " << WSAGetLastError() << std::endl;
        freeaddrinfo(result);
        WSACleanup();
        return 1;
    }

    // Bind socket ke alamat dan port
    iResult = bind(ListenSocket, result->ai_addr, (int)result->ai_addrlen);
    if (iResult == SOCKET_ERROR) {
        std::cerr << "Bind gagal dengan error: " << WSAGetLastError() << std::endl;
        freeaddrinfo(result);
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }

    freeaddrinfo(result);

    // Mulai mendengarkan koneksi
    iResult = listen(ListenSocket, SOMAXCONN);
    if (iResult == SOCKET_ERROR) {
        std::cerr << "Listen gagal dengan error: " << WSAGetLastError() << std::endl;
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }

    std::cout << "==================================================" << std::endl;
    std::cout << "  OBLIVION HACK SHIELD - Server Component" << std::endl;
    std::cout << "  Version 1.0 - Ragnarok Online Protection" << std::endl;
    std::cout << "==================================================" << std::endl;
    std::cout << "[INFO] Server berjalan dan mendengarkan di port " << listenPortText << std::endl;
    std::cout << "[INFO] Ban list file: " << GetFilePath(BAN_LIST_FILE) << std::endl;
    std::cout << "[INFO] Violation log file: " << GetFilePath(VIOLATION_LOG_FILE) << std::endl;
    std::cout << "[INFO] Menunggu koneksi dari client..." << std::endl;
    std::cout << "==================================================" << std::endl;

    // Read heartbeat overrides using the same strict numeric parsing as the Linux server.
    auto readEnvUint = [](const char* name, uint32_t defaultValue) {
        char buffer[64] = {};
        const DWORD length = GetEnvironmentVariableA(name, buffer, static_cast<DWORD>(sizeof(buffer)));
        if (length == 0) return defaultValue;
        if (length >= sizeof(buffer)) {
            std::cerr << "[HB CFG] Invalid value for " << name
                      << "; using default " << defaultValue << std::endl;
            return defaultValue;
        }

        errno = 0;
        char* end = nullptr;
        const unsigned long long parsed = std::strtoull(buffer, &end, 10);
        if (errno != 0 || end == buffer || *end != 0 ||
            parsed > (std::numeric_limits<uint32_t>::max)()) {
            std::cerr << "[HB CFG] Invalid value for " << name
                      << "; using default " << defaultValue << std::endl;
            return defaultValue;
        }
        return static_cast<uint32_t>(parsed);
    };

    Oblivion::HeartbeatConfig globalHbCfg;
    globalHbCfg.interval_ms = readEnvUint("OBLV_HB_INTERVAL_MS", globalHbCfg.interval_ms);
    globalHbCfg.jitter_ms = readEnvUint("OBLV_HB_JITTER_MS", globalHbCfg.jitter_ms);
    globalHbCfg.timeout_ms = readEnvUint("OBLV_HB_TIMEOUT_MS", globalHbCfg.timeout_ms);
    globalHbCfg.max_consecutive_miss = readEnvUint("OBLV_HB_MAX_MISS", globalHbCfg.max_consecutive_miss);
    globalHbCfg.rtt_warn_ms = readEnvUint("OBLV_HB_RTT_WARN_MS", globalHbCfg.rtt_warn_ms);

    if (globalHbCfg.interval_ms < 100 || globalHbCfg.interval_ms > 60000 ||
        globalHbCfg.jitter_ms > 10000 ||
        globalHbCfg.timeout_ms < 250 || globalHbCfg.timeout_ms > 120000 ||
        globalHbCfg.max_consecutive_miss < 1 || globalHbCfg.max_consecutive_miss > 10 ||
        globalHbCfg.rtt_warn_ms > 60000) {
        std::cerr << "[FATAL] Heartbeat configuration outside supported bounds." << std::endl;
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }

    std::cout << "[HB CFG] interval=" << globalHbCfg.interval_ms << "ms jitter=" << globalHbCfg.jitter_ms
              << "ms timeout=" << globalHbCfg.timeout_ms << "ms maxMiss=" << globalHbCfg.max_consecutive_miss
              << " rttWarn=" << globalHbCfg.rtt_warn_ms << "ms" << std::endl;

    // Loop utama untuk menerima koneksi
    while (true) {
        // Terima koneksi dari client
        ClientSocket = accept(ListenSocket, NULL, NULL);
        if (ClientSocket == INVALID_SOCKET) {
            std::cerr << "[ERROR] Accept gagal dengan error: " << WSAGetLastError() << std::endl;
            continue; // Jangan shutdown server, coba accept lagi
        }

        std::cout << "\n[CONNECTION] New client connected" << std::endl;
        
        // Buat thread baru untuk menangani client agar server bisa menerima client lain
        // Pass the validated heartbeat configuration into each client session.
        try {
            std::thread clientThread(HandleClient, ClientSocket, globalHbCfg);
            clientThread.detach();
        } catch (const std::exception& e) {
            std::cerr << "[ERROR] Failed to start client handler thread: " << e.what() << std::endl;
            closesocket(ClientSocket);
        } // Lepaskan thread agar bisa berjalan mandiri
    }

    // Cleanup (tidak akan pernah tercapai dalam loop tak terbatas ini)
    closesocket(ListenSocket);
    WSACleanup();

    return 0;
}
