#pragma once

#include <windows.h>
#include <thread>
#include <atomic>
#include <set>

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

        AntiDebug* m_pAntiDebug;
        InjectionScanner* m_pInjectionScanner;
        AntiSuspend* m_pAntiSuspend;
        OverlayScanner* m_pOverlayScanner;
        MemoryScanner* m_pMemoryScanner;
        DigitalSignatureValidator* m_pDigitalSignatureValidator;
        IATHookScanner* m_pIATHookScanner;
        AdvancedProcessHeuristics* m_pAdvancedHeuristics;
        
        // Cache untuk menghindari log spam
        std::set<DWORD> m_scannedProcesses;
    };
}