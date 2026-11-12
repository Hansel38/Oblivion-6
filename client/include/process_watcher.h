#pragma once

#include <windows.h>
#include <thread>
#include <atomic>
#include <set>
#include <map>
#include <memory>
#include <condition_variable>
#include <mutex>

namespace Oblivion {
    // Forward declarations
    class AntiDebug;
    class InjectionScanner;
    class AntiSuspend;
    class OverlayScanner;
    class MemoryScanner;
    class DigitalSignatureValidator;
    class IATHookScanner;
    class AdvancedProcessHeuristics;

    class ProcessWatcher {
    public:
        ProcessWatcher();
        ~ProcessWatcher();

        void Start();
        void Stop();

    private:
        void WatcherLoop();
        void PerformScan();

        std::thread m_watcherThread;
        std::atomic<bool> m_isRunning;
        std::mutex m_waitMutex;
        std::condition_variable m_waitCondition;

        std::unique_ptr<AntiDebug> m_pAntiDebug;
        std::unique_ptr<InjectionScanner> m_pInjectionScanner;
        std::unique_ptr<AntiSuspend> m_pAntiSuspend;
        std::unique_ptr<OverlayScanner> m_pOverlayScanner;
        std::unique_ptr<MemoryScanner> m_pMemoryScanner;
        std::unique_ptr<DigitalSignatureValidator> m_pDigitalSignatureValidator;
        std::unique_ptr<IATHookScanner> m_pIATHookScanner;
        std::unique_ptr<AdvancedProcessHeuristics> m_pAdvancedHeuristics;
        
        // Cache untuk menghindari log spam
        std::map<DWORD, ULONGLONG> m_scannedProcesses;
    };
}