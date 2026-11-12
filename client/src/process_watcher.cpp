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

// Forward declaration
extern void ReportViolationAndExit(const std::wstring& message, const std::string& type, const std::string& details);

namespace Oblivion {
    ProcessWatcher::ProcessWatcher() : m_isRunning(false) {
        std::cout << "[ProcessWatcher] Initializing components..." << std::endl;
        try {
            m_pAntiDebug = new AntiDebug();
            m_pInjectionScanner = new InjectionScanner();
            m_pAntiSuspend = new AntiSuspend();
            m_pOverlayScanner = new OverlayScanner();
            m_pMemoryScanner = new MemoryScanner();
            m_pDigitalSignatureValidator = new DigitalSignatureValidator();
            m_pIATHookScanner = new IATHookScanner();
            m_pAdvancedHeuristics = new AdvancedProcessHeuristics();
            
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
        std::cout << "[ProcessWatcher] Destructor called, stopping..." << std::endl;
        Stop();
        
        // Delete all components safely
        if (m_pAntiDebug) { delete m_pAntiDebug; m_pAntiDebug = nullptr; }
        if (m_pInjectionScanner) { delete m_pInjectionScanner; m_pInjectionScanner = nullptr; }
        if (m_pAntiSuspend) { delete m_pAntiSuspend; m_pAntiSuspend = nullptr; }
        if (m_pOverlayScanner) { delete m_pOverlayScanner; m_pOverlayScanner = nullptr; }
        if (m_pMemoryScanner) { delete m_pMemoryScanner; m_pMemoryScanner = nullptr; }
        if (m_pDigitalSignatureValidator) { delete m_pDigitalSignatureValidator; m_pDigitalSignatureValidator = nullptr; }
        if (m_pIATHookScanner) { delete m_pIATHookScanner; m_pIATHookScanner = nullptr; }
        if (m_pAdvancedHeuristics) { delete m_pAdvancedHeuristics; m_pAdvancedHeuristics = nullptr; }
        
        std::cout << "[ProcessWatcher] Destructor complete" << std::endl;
    }

    void ProcessWatcher::Start() {
        if (m_isRunning) {
            std::cout << "[ProcessWatcher] Already running, ignoring Start() call" << std::endl;
            return;
        }
        
        std::cout << "[ProcessWatcher] Starting monitoring system..." << std::endl;
        m_isRunning = true;
        
        // Mulai thread pengawas terlebih dahulu
        m_pAntiSuspend->Start();
        
        // Lalu mulai thread pemantauan utama
        m_watcherThread = std::thread(&ProcessWatcher::WatcherLoop, this);
        std::cout << "[ProcessWatcher] Monitoring thread started" << std::endl;
    }

    void ProcessWatcher::Stop() {
        if (!m_isRunning) {
            return;
        }
        
        std::cout << "[ProcessWatcher] Stopping monitoring system..." << std::endl;
        m_isRunning = false;
        
        // Wait for watcher thread to finish
        if (m_watcherThread.joinable()) {
            m_watcherThread.join();
        }
        
        // Hentikan thread pengawas setelah thread utama berhenti
        m_pAntiSuspend->Stop();
        std::cout << "[ProcessWatcher] Stopped successfully" << std::endl;
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

                Sleep(sleepDurationMs);
            }
        }
    }

    void ProcessWatcher::PerformScan() {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            return;
        }

        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);

        if (Process32First(hSnapshot, &pe32)) {
            do {
                std::wstring processName = pe32.szExeFile;
                DWORD processId = pe32.th32ProcessID;

                // Deteksi blacklist
                if (IsProcessBlacklisted(processName)) {
                    std::wcout << L"[DETECTION] Blacklisted process detected: " << processName << std::endl;
                    m_isRunning = false;
                    std::string details_utf8;
                    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &processName[0], (int)processName.size(), NULL, 0, NULL, NULL);
                    if (size_needed > 0) {
                        details_utf8.assign(size_needed, 0);
                        WideCharToMultiByte(CP_UTF8, 0, &processName[0], (int)processName.size(), &details_utf8[0], size_needed, NULL, NULL);
                    }
                    std::cout << "[VIOLATION] Reporting to server: PROCESS_DETECTED - " << details_utf8 << std::endl;
                    ReportViolationAndExit(L"", "PROCESS_DETECTED", details_utf8);
                }

                // Cek apakah proses sudah pernah di-scan
                bool isNewProcess = m_scannedProcesses.find(processId) == m_scannedProcesses.end();
                
                if (isNewProcess) {
                    // Tambahkan ke cache
                    m_scannedProcesses.insert(processId);
                    
                    // Memory scan untuk proses non-whitelist
                    if (Oblivion::ShouldPerformMemoryScan(processName)) {
                        std::wcout << L"[SCAN] Memory scan scheduled for: " << processName << L" (PID: " << processId << L")" << std::endl;
                    }

                    // Heuristik perilaku
                    if (Oblivion::IsSuspiciousBehavior(processId)) {
                        Oblivion::LogSuspiciousProcess(processName, processId, "Suspicious module or injection detected");
                        // Optional: langsung blokir
                        std::string details_utf8;
                        int size_needed = WideCharToMultiByte(CP_UTF8, 0, &processName[0], (int)processName.size(), NULL, 0, NULL, NULL);
                        if (size_needed > 0) {
                            details_utf8.assign(size_needed, 0);
                            WideCharToMultiByte(CP_UTF8, 0, &processName[0], (int)processName.size(), &details_utf8[0], size_needed, NULL, NULL);
                        }
                        ReportViolationAndExit(L"", "SUSPICIOUS_BEHAVIOR", details_utf8);
                    }
                }

            } while (Process32Next(hSnapshot, &pe32) && m_isRunning);
        }

        CloseHandle(hSnapshot);
    }
}