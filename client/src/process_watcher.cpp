#include "pch.h"
#include "process_watcher.h"
#include "blacklist.h"
#include "AntiDebug.h"
#include "injection_scanner.h"
#include "anti_suspend.h"
#include "overlay_scanner.h"
#include "memory_scanner.h"
#include "digital_signature_validator.h"
#include "iat_hook_scanner.h"
#include "advanced_process_heuristics.h"
#include <tlhelp32.h>
#include <iostream>
#include <vector>
#include <random>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <stdexcept>

// Forward declaration
extern void ReportViolationAndExit(const std::wstring& message, const std::string& type, const std::string& details);

namespace Oblivion {
    ProcessWatcher::ProcessWatcher() : m_isRunning(false) {
        std::cout << "[ProcessWatcher] Initializing components..." << std::endl;
        try {
            m_pAntiDebug = std::make_unique<AntiDebug>();
            m_pInjectionScanner = std::make_unique<InjectionScanner>();
            m_pAntiSuspend = std::make_unique<AntiSuspend>();
            m_pOverlayScanner = std::make_unique<OverlayScanner>();
            m_pMemoryScanner = std::make_unique<MemoryScanner>();
            m_pDigitalSignatureValidator = std::make_unique<DigitalSignatureValidator>();
            m_pIATHookScanner = std::make_unique<IATHookScanner>();
            m_pAdvancedHeuristics = std::make_unique<AdvancedProcessHeuristics>();
            
            // Set heartbeat callback untuk AdvancedHeuristics
            m_pAdvancedHeuristics->SetHeartbeatCallback([this]() {
                if (m_isRunning && m_pAntiSuspend) {
                    m_pAntiSuspend->UpdateHeartbeat();
                }
            });
            
            std::cout << "[ProcessWatcher] All components initialized successfully" << std::endl;
        } catch (const std::exception& e) {
            std::cerr << "[ProcessWatcher] ERROR: Failed to initialize: " << e.what() << std::endl;
            throw;
        }
    }

    ProcessWatcher::~ProcessWatcher() {
        // Stop worker threads before unique_ptr members are destroyed.
        Stop();
    }

    void ProcessWatcher::Start() {
        if (m_isRunning.load()) {
            std::cout << "[ProcessWatcher] Already running, ignoring Start() call" << std::endl;
            return;
        }

        // A previous worker may have ended without Stop() being called.
        if (m_watcherThread.joinable()) {
            if (m_watcherThread.get_id() == std::this_thread::get_id()) {
                throw std::logic_error("ProcessWatcher cannot restart from its own worker thread");
            }
            m_watcherThread.join();
        }

        bool expected = false;
        if (!m_isRunning.compare_exchange_strong(expected, true)) return;

        m_scannedProcesses.clear();
        std::cout << "[ProcessWatcher] Starting monitoring system..." << std::endl;
        try {
            m_pAntiSuspend->Start();
            m_watcherThread = std::thread(&ProcessWatcher::WatcherLoop, this);
            std::cout << "[ProcessWatcher] Monitoring thread started" << std::endl;
        } catch (...) {
            // Roll back both lifecycle states if either thread fails to start.
            m_isRunning.store(false);
            m_pAntiSuspend->Stop();
            throw;
        }
    }

    void ProcessWatcher::Stop() {
        const bool wasRunning = m_isRunning.exchange(false);
        m_waitCondition.notify_all();
        if (wasRunning) {
            std::cout << "[ProcessWatcher] Stopping monitoring system..." << std::endl;
        }

        if (m_watcherThread.joinable() &&
            m_watcherThread.get_id() != std::this_thread::get_id()) {
            m_watcherThread.join();
        }

        if (m_pAntiSuspend) {
            m_pAntiSuspend->Stop();
        }

        if (wasRunning) {
            std::cout << "[ProcessWatcher] Stopped successfully" << std::endl;
        }
    }

    void ProcessWatcher::WatcherLoop() {
        auto heartbeat = [this]() {
            if (m_isRunning) {
                m_pAntiSuspend->UpdateHeartbeat();
            }
        };

        heartbeat();
        // Pemindaian awal
        PerformScan();
        heartbeat();

        if (m_isRunning) m_pAntiDebug->PerformCheck();
        heartbeat();

        if (m_isRunning) m_pInjectionScanner->PerformScan();
        heartbeat();

        if (m_isRunning) m_pOverlayScanner->PerformScan();
        heartbeat();

        if (m_isRunning) m_pMemoryScanner->PerformScan();
        heartbeat();

        if (m_isRunning) m_pDigitalSignatureValidator->PerformScan();
        heartbeat();

        if (m_isRunning) m_pIATHookScanner->PerformScan();
        heartbeat();

        if (m_isRunning) m_pAdvancedHeuristics->PerformScan();
        heartbeat();

        // Gunakan generator angka acak modern untuk interval tidur acak
        std::mt19937 rng(static_cast<unsigned int>(
            std::chrono::high_resolution_clock::now().time_since_epoch().count()));
        std::uniform_int_distribution<int> sleepDist(500, 3000);

        // Loop pemantauan real-time
        while (m_isRunning) {
            heartbeat();

            PerformScan();

            if (m_isRunning) m_pAntiDebug->PerformCheck();

            if (m_isRunning) m_pInjectionScanner->PerformScan();

            if (m_isRunning) m_pOverlayScanner->PerformScan();

            if (m_isRunning) m_pMemoryScanner->PerformScan();

            if (m_isRunning) m_pDigitalSignatureValidator->PerformScan();

            if (m_isRunning) m_pIATHookScanner->PerformScan();

            if (m_isRunning) m_pAdvancedHeuristics->PerformScan();

            if (m_isRunning) {
                const int sleepDurationMs = sleepDist(rng);

#ifdef _DEBUG
                // Log waktu eksekusi loop untuk verifikasi interval acak.
                auto now = std::chrono::system_clock::now();
                auto tt = std::chrono::system_clock::to_time_t(now);
                auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
                std::tm localTime{};
                localtime_s(&localTime, &tt);

                std::ostringstream oss;
                oss << "[ProcessWatcher] Scan loop at "
                    << std::put_time(&localTime, "%Y-%m-%d %H:%M:%S")
                    << '.' << std::setw(3) << std::setfill('0') << ms.count()
                    << " sleeping " << sleepDurationMs << " ms";

                const auto message = oss.str();
                OutputDebugStringA(message.c_str());
                OutputDebugStringA("\n");
#endif

                std::unique_lock<std::mutex> waitLock(m_waitMutex);
                m_waitCondition.wait_for(
                    waitLock, std::chrono::milliseconds(sleepDurationMs),
                    [this]() { return !m_isRunning.load(); });
            }
        }
    }

    void ProcessWatcher::PerformScan() {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            const DWORD error = GetLastError();
            ReportViolationAndExit(
                L"", "PROCESS_ENUMERATION_UNAVAILABLE",
                "CreateToolhelp32Snapshot failed; error=" + std::to_string(error));
            return;
        }

        PROCESSENTRY32 pe32{};
        pe32.dwSize = sizeof(PROCESSENTRY32);
        std::set<DWORD> activeProcesses;

        if (!Process32First(hSnapshot, &pe32)) {
            const DWORD error = GetLastError();
            CloseHandle(hSnapshot);
            ReportViolationAndExit(
                L"", "PROCESS_ENUMERATION_UNAVAILABLE",
                "Process32First failed; error=" + std::to_string(error));
            return;
        }

        BOOL hasNext = TRUE;
        do {
            std::wstring processName = pe32.szExeFile;
            DWORD processId = pe32.th32ProcessID;
            activeProcesses.insert(processId);

            // Deteksi blacklist
            if (IsProcessBlacklisted(processName)) {
                std::wcout << L"[DETECTION] Blacklisted process detected: " << processName << std::endl;
                m_isRunning = false;
                std::string details_utf8;
                int size_needed = WideCharToMultiByte(CP_UTF8, 0, processName.c_str(),
                    static_cast<int>(processName.size()), NULL, 0, NULL, NULL);
                if (size_needed > 0) {
                    details_utf8.assign(size_needed, 0);
                    WideCharToMultiByte(CP_UTF8, 0, processName.c_str(),
                        static_cast<int>(processName.size()), &details_utf8[0], size_needed, NULL, NULL);
                }
                ReportViolationAndExit(L"", "PROCESS_DETECTED", details_utf8);
                return;
            }

            // Cek apakah proses sudah pernah di-scan
            const bool isNewProcess =
                m_scannedProcesses.find(processId) == m_scannedProcesses.end();

            if (isNewProcess) {
                // Tambahkan ke cache
                m_scannedProcesses.insert(processId);

                if (Oblivion::ShouldPerformMemoryScan(processName)) {
                    std::wcout << L"[SCAN] Memory scan scheduled for: "
                               << processName << L" (PID: " << processId << L")" << std::endl;
                }

                if (Oblivion::IsSuspiciousBehavior(processId)) {
                    Oblivion::LogSuspiciousProcess(
                        processName, processId, "Suspicious module or injection detected");
                    std::string details_utf8;
                    const int size_needed = WideCharToMultiByte(
                        CP_UTF8, 0, processName.c_str(),
                        static_cast<int>(processName.size()), NULL, 0, NULL, NULL);
                    if (size_needed > 0) {
                        details_utf8.assign(static_cast<size_t>(size_needed), 0);
                        WideCharToMultiByte(CP_UTF8, 0, processName.c_str(),
                            static_cast<int>(processName.size()), &details_utf8[0],
                            size_needed, NULL, NULL);
                    }
                    ReportViolationAndExit(L"", "SUSPICIOUS_BEHAVIOR", details_utf8);
                    return;
                }
            }

            if (!m_isRunning.load()) {
                break;
            }
            hasNext = Process32Next(hSnapshot, &pe32);
        } while (hasNext);

        const DWORD enumerationError = hasNext ? ERROR_SUCCESS : GetLastError();
        CloseHandle(hSnapshot);

        if (m_isRunning.load() && !hasNext && enumerationError != ERROR_NO_MORE_FILES) {
            ReportViolationAndExit(
                L"", "PROCESS_ENUMERATION_UNAVAILABLE",
                "Process32Next failed before enumeration completed; error=" +
                    std::to_string(enumerationError));
            return;
        }

        // Forget PIDs that are no longer present so the cache stays bounded
        // and a PID can be examined again after the process exits.
        for (auto it = m_scannedProcesses.begin(); it != m_scannedProcesses.end();) {
            if (activeProcesses.find(*it) == activeProcesses.end()) {
                it = m_scannedProcesses.erase(it);
            } else {
                ++it;
            }
        }
    }
}