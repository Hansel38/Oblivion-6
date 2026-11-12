#include "pch.h"
#include "self_integrity_guard.h"

#include <algorithm>
#include <chrono>
#include <fstream>

// Forward declaration
extern void ReportViolationAndExit(const std::wstring& message, const std::string& type, const std::string& details);

namespace {
    constexpr auto kVerificationInterval = std::chrono::seconds(5);

    bool IsCodeSection(const IMAGE_SECTION_HEADER& section) {
        const auto characteristics = section.Characteristics;
        return (characteristics & IMAGE_SCN_CNT_CODE) != 0 &&
               (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
    }
}

namespace Oblivion {
    SelfIntegrityGuard::SelfIntegrityGuard(HMODULE moduleHandle)
        : m_module(moduleHandle),
          m_running(false) {
        if (m_module) {
            wchar_t pathBuffer[MAX_PATH] = { 0 };
            if (GetModuleFileNameW(m_module, pathBuffer, MAX_PATH) != 0) {
                m_modulePath.assign(pathBuffer);
            }
        }
    }

    SelfIntegrityGuard::~SelfIntegrityGuard() {
        Stop();
    }

    bool SelfIntegrityGuard::Start() {
        if (m_running.load() || !m_module || m_modulePath.empty()) {
            return false;
        }

        if (!LoadDiskImage()) {
            return false;
        }

        if (!ParseRelocations()) {
            return false;
        }

        if (!VerifySectionsOnce()) {
            return false;
        }

        m_running = true;
        m_worker = std::thread(&SelfIntegrityGuard::MonitoringLoop, this);
        return true;
    }

    void SelfIntegrityGuard::Stop() {
        if (!m_running.load()) {
            return;
        }

        m_running = false;
        if (m_worker.joinable()) {
            m_worker.join();
        }
    }

    bool SelfIntegrityGuard::LoadDiskImage() {
        if (!m_diskImage.empty()) {
            return true;
        }

        std::ifstream file(m_modulePath, std::ios::binary | std::ios::ate);
        if (!file.is_open()) {
            return false;
        }

        const auto fileSize = file.tellg();
        if (fileSize <= 0) {
            return false;
        }

        const auto sizeValue = static_cast<std::streamsize>(fileSize);
        m_diskImage.resize(static_cast<size_t>(sizeValue));
        file.seekg(0, std::ios::beg);
        file.read(reinterpret_cast<char*>(m_diskImage.data()), sizeValue);
        return file.good();
    }

    void SelfIntegrityGuard::MonitoringLoop() {
        while (m_running.load()) {
            if (!VerifySectionsOnce()) {
                // ReportViolationAndExit already called inside VerifySectionsOnce.
                return;
            }

            auto slept = std::chrono::milliseconds(0);
            while (slept < kVerificationInterval && m_running.load()) {
                Sleep(100);
                slept += std::chrono::milliseconds(100);
            }
        }
    }

    bool SelfIntegrityGuard::VerifySectionsOnce() const {
        auto* moduleBase = reinterpret_cast<const uint8_t*>(m_module);
        const auto* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(moduleBase);
        if (!dosHeader || dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            return false;
        }

        const auto* ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(moduleBase + dosHeader->e_lfanew);
        if (!ntHeaders || ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            return false;
        }

        const auto* fileDosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(m_diskImage.data());
        if (!fileDosHeader || fileDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            return false;
        }

        const auto* fileNtHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(m_diskImage.data() + fileDosHeader->e_lfanew);
        if (!fileNtHeaders || fileNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
            return false;
        }

        const auto sectionCount = ntHeaders->FileHeader.NumberOfSections;
        auto* currentSection = IMAGE_FIRST_SECTION(ntHeaders);

        for (WORD i = 0; i < sectionCount; ++i, ++currentSection) {
            if (!IsCodeSection(*currentSection)) {
                continue;
            }

            if (!CompareSection(*currentSection)) {
                size_t length = 0;
                while (length < IMAGE_SIZEOF_SHORT_NAME && currentSection->Name[length] != '\0') {
                    ++length;
                }
                const std::string sectionName(reinterpret_cast<const char*>(currentSection->Name), length);
                ReportTamper(sectionName);
                return false;
            }
        }

        return true;
    }

    bool SelfIntegrityGuard::CompareSection(const IMAGE_SECTION_HEADER& section) const {
        auto* moduleBase = reinterpret_cast<const uint8_t*>(m_module);
        const auto* sectionMemory = moduleBase + section.VirtualAddress;

        size_t sectionSize = static_cast<size_t>(section.SizeOfRawData);
        const size_t virtualSize = static_cast<size_t>(section.Misc.VirtualSize);
        if (virtualSize > 0 && virtualSize < sectionSize) {
            sectionSize = virtualSize;
        }

        if (sectionSize == 0) {
            return true;
        }

        if (section.PointerToRawData + sectionSize > m_diskImage.size()) {
            return false;
        }

        const auto* sectionOnDisk = m_diskImage.data() + section.PointerToRawData;

        std::vector<std::pair<size_t, size_t>> skipIntervals;
        const DWORD sectionStartRva = section.VirtualAddress;
        const DWORD sectionEndRva = sectionStartRva + static_cast<DWORD>(sectionSize);
        BuildSkipIntervals(sectionStartRva, sectionEndRva, skipIntervals);

        if (skipIntervals.empty()) {
            return memcmp(sectionMemory, sectionOnDisk, sectionSize) == 0;
        }

        size_t currentOffset = 0;
        for (const auto& interval : skipIntervals) {
            const size_t start = interval.first;
            const size_t end = interval.second;
            if (currentOffset < start) {
                const size_t length = start - currentOffset;
                if (memcmp(sectionMemory + currentOffset, sectionOnDisk + currentOffset, length) != 0) {
                    return false;
                }
            }
            currentOffset = std::max(currentOffset, end);
        }

        if (currentOffset < sectionSize) {
            const size_t length = sectionSize - currentOffset;
            if (memcmp(sectionMemory + currentOffset, sectionOnDisk + currentOffset, length) != 0) {
                return false;
            }
        }

        return true;
    }

    void SelfIntegrityGuard::ReportTamper(const std::string& sectionName) const {
        std::string details = "Self integrity mismatch detected";
        if (!sectionName.empty()) {
            details += " in section ";
            details += sectionName;
        }
        ReportViolationAndExit(L"", "SELF_TAMPER_DETECTED", details);
    }

    bool SelfIntegrityGuard::ParseRelocations() {
        m_relocationSpans.clear();

        if (m_diskImage.empty()) {
            return false;
        }

        const auto* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(m_diskImage.data());
        if (!dosHeader || dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            return false;
        }

        const auto* ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(m_diskImage.data() + dosHeader->e_lfanew);
        if (!ntHeaders || ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            return false;
        }

        const auto& relocDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (relocDirectory.VirtualAddress == 0 || relocDirectory.Size == 0) {
            return true;
        }

        DWORD relocFileOffset = 0;
        if (!RvaToFileRange(relocDirectory.VirtualAddress, relocDirectory.Size, relocFileOffset)) {
            return false;
        }

        size_t remaining = relocDirectory.Size;
        const uint8_t* cursor = m_diskImage.data() + relocFileOffset;

        while (remaining >= sizeof(IMAGE_BASE_RELOCATION)) {
            const auto* block = reinterpret_cast<const IMAGE_BASE_RELOCATION*>(cursor);
            if (block->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION) || block->SizeOfBlock > remaining) {
                break;
            }

            const size_t entryCount = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            const auto* entry = reinterpret_cast<const WORD*>(cursor + sizeof(IMAGE_BASE_RELOCATION));

            for (size_t i = 0; i < entryCount; ++i) {
                const WORD typeOffset = entry[i];
                const WORD type = typeOffset >> 12;
                const WORD offset = typeOffset & 0x0FFF;

                size_t spanSize = 0;
                switch (type) {
                case IMAGE_REL_BASED_ABSOLUTE:
                    continue;
                case IMAGE_REL_BASED_HIGHLOW:
                    spanSize = sizeof(DWORD);
                    break;
                case IMAGE_REL_BASED_DIR64:
                    spanSize = sizeof(ULONGLONG);
                    break;
                default:
                    continue;
                }

                const DWORD rva = block->VirtualAddress + offset;
                m_relocationSpans.push_back({ rva, spanSize });
            }

            cursor += block->SizeOfBlock;
            remaining -= block->SizeOfBlock;
        }

        std::sort(m_relocationSpans.begin(), m_relocationSpans.end(), [](const RelocationSpan& a, const RelocationSpan& b) {
            return a.rva < b.rva;
            });

        return true;
    }

    bool SelfIntegrityGuard::RvaToFileRange(DWORD rva, DWORD size, DWORD& fileOffset) const {
        if (m_diskImage.empty()) {
            return false;
        }

        const auto* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(m_diskImage.data());
        if (!dosHeader || dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            return false;
        }

        const auto* ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(m_diskImage.data() + dosHeader->e_lfanew);
        if (!ntHeaders || ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            return false;
        }

        const DWORD imageSize = ntHeaders->OptionalHeader.SizeOfImage;
        if (size == 0 || rva >= imageSize) {
            return false;
        }

        const auto* section = IMAGE_FIRST_SECTION(ntHeaders);
        for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i, ++section) {
            const DWORD sectionStart = section->VirtualAddress;
            const DWORD sectionSize = std::max(section->Misc.VirtualSize, section->SizeOfRawData);
            const DWORD sectionEnd = sectionStart + sectionSize;

            if (rva >= sectionStart && rva < sectionEnd) {
                const DWORD offsetWithinSection = rva - sectionStart;
                if (offsetWithinSection + size > sectionSize) {
                    return false;
                }

                fileOffset = section->PointerToRawData + offsetWithinSection;
                if (fileOffset + size > m_diskImage.size()) {
                    return false;
                }
                return true;
            }
        }

        // RVA within headers
        if (rva < ntHeaders->OptionalHeader.SizeOfHeaders) {
            fileOffset = rva;
            if (fileOffset + size > m_diskImage.size()) {
                return false;
            }
            return true;
        }

        return false;
    }

    void SelfIntegrityGuard::BuildSkipIntervals(DWORD sectionStart, DWORD sectionEnd, std::vector<std::pair<size_t, size_t>>& skips) const {
        skips.clear();
        if (m_relocationSpans.empty() || sectionStart >= sectionEnd) {
            return;
        }

        for (const auto& span : m_relocationSpans) {
            const DWORD spanStart = span.rva;
            const DWORD spanEnd = span.rva + static_cast<DWORD>(span.size);

            if (spanEnd <= sectionStart || spanStart >= sectionEnd) {
                continue;
            }

            const auto relativeStart = static_cast<size_t>(std::max<DWORD>(spanStart, sectionStart) - sectionStart);
            const auto relativeEnd = static_cast<size_t>(std::min<DWORD>(spanEnd, sectionEnd) - sectionStart);
            if (relativeStart < relativeEnd) {
                skips.emplace_back(relativeStart, relativeEnd);
            }
        }

        if (skips.empty()) {
            return;
        }

        std::sort(skips.begin(), skips.end());

        std::vector<std::pair<size_t, size_t>> merged;
        merged.reserve(skips.size());

        auto current = skips.front();
        for (size_t i = 1; i < skips.size(); ++i) {
            const auto& interval = skips[i];
            if (interval.first <= current.second) {
                current.second = std::max(current.second, interval.second);
            } else {
                merged.push_back(current);
                current = interval;
            }
        }
        merged.push_back(current);

        skips.swap(merged);
    }
}

