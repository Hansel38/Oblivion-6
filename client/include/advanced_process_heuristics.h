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
        enum class ModuleScanResult {
            Clean,
            Suspicious,
            Incomplete
        };

        ModuleScanResult ContainsSuspiciousModule(
            DWORD processId,
            std::wstring& matchedModule,
            std::wstring& scanIssue) const;
        
        // Window class detection
        bool HasSuspiciousWindowClass(DWORD processId, std::wstring& matchedClass) const;
        
        // Window title pattern detection
        bool HasSuspiciousWindowTitle(DWORD processId, std::wstring& matchedPattern) const;
        
        // Path-based detection
        enum class PathScanResult {
            Clean,
            Suspicious,
            Incomplete
        };

        PathScanResult HasSuspiciousPath(
            DWORD processId,
            std::wstring& matchedPath,
            std::wstring& scanIssue) const;
        
        // Handle-based detection (ULTIMATE - detects any memory scanner)
        enum class HandleScanResult {
            Clean,
            Suspicious,
            Incomplete
        };

        HandleScanResult HasSuspiciousHandleToGame(
            DWORD gameProcessId,
            std::wstring& suspiciousProcess,
            std::wstring& scanIssue) const;
        
        // Behavioral detection
        bool HasSuspiciousBehavior(DWORD processId, std::wstring& behaviorType) const;
        
        // Memory signature detection
        enum class MemoryScanResult {
            Clean,
            Suspicious,
            Incomplete
        };

        MemoryScanResult HasSuspiciousMemorySignature(
            DWORD processId,
            std::wstring& matchedPattern,
            std::wstring& scanIssue) const;

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

