#pragma once

#include <windows.h>
#include <string>
#include <functional>

namespace Oblivion {
    class AdvancedProcessHeuristics {
    public:
        AdvancedProcessHeuristics();
        ~AdvancedProcessHeuristics();

        void PerformScan();
        
        // Set callback untuk heartbeat update (untuk mencegah timeout di scan yang lama)
        void SetHeartbeatCallback(std::function<void()> callback);

    private:
        AdvancedProcessHeuristics(const AdvancedProcessHeuristics&) = delete;
        AdvancedProcessHeuristics& operator=(const AdvancedProcessHeuristics&) = delete;

        // DLL detection
        bool ContainsSuspiciousModule(DWORD processId, std::wstring& matchedModule) const;
        
        // Window class detection
        bool HasSuspiciousWindowClass(DWORD processId, std::wstring& matchedClass) const;
        
        // Window title pattern detection
        bool HasSuspiciousWindowTitle(DWORD processId, std::wstring& matchedPattern) const;
        
        // Path-based detection
        bool HasSuspiciousPath(DWORD processId, std::wstring& matchedPath) const;
        
        // Handle-based detection (ULTIMATE - detects any memory scanner)
        bool HasSuspiciousHandleToGame(DWORD gameProcessId, std::wstring& suspiciousProcess) const;
        
        // Behavioral detection
        bool HasSuspiciousBehavior(DWORD processId, std::wstring& behaviorType) const;
        
        // Memory signature detection
        bool HasSuspiciousMemorySignature(DWORD processId, std::wstring& matchedPattern) const;

        // Helper functions
        std::string BuildHeuristicDetails(const std::wstring& processName,
                                          DWORD processId,
                                          const std::wstring& detectionType,
                                          const std::wstring& indicator) const;

        std::string ConvertWideToUtf8(const std::wstring& input) const;
        
        // Heartbeat callback untuk mencegah timeout
        std::function<void()> m_heartbeatCallback;
    };

    // Global helper functions for advanced heuristics
    bool ShouldPerformMemoryScan(const std::wstring& processName);
    bool IsSuspiciousBehavior(DWORD processId);
    void LogSuspiciousProcess(const std::wstring& processName, DWORD processId, const std::string& reason);
}

