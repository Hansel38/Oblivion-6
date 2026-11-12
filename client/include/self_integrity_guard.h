#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#ifdef max
#undef max
#endif
#ifdef min
#undef min
#endif

#include <atomic>
#include <string>
#include <utility>
#include <thread>
#include <vector>

namespace Oblivion {
    struct RelocationSpan {
        DWORD rva;
        size_t size;
    };

    class SelfIntegrityGuard {
    public:
        explicit SelfIntegrityGuard(HMODULE moduleHandle);
        ~SelfIntegrityGuard();

        bool Start();
        void Stop();

    private:
        bool LoadDiskImage();
        bool ParseRelocations();
        bool RvaToFileRange(DWORD rva, DWORD size, DWORD& fileOffset) const;
        bool VerifySectionsOnce() const;
        void MonitoringLoop();
        bool CompareSection(const IMAGE_SECTION_HEADER& section) const;
        void ReportTamper(const std::string& sectionName) const;
        void BuildSkipIntervals(DWORD sectionStart, DWORD sectionEnd, std::vector<std::pair<size_t, size_t>>& skips) const;

        HMODULE m_module;
        std::wstring m_modulePath;
        std::vector<uint8_t> m_diskImage;
        std::vector<RelocationSpan> m_relocationSpans;
        std::atomic<bool> m_running;
        std::thread m_worker;
    };
}

