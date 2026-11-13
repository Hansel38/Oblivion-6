#include "pch.h"
#include "self_integrity_guard.h"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <fstream>
#include <limits>
#include <new>
#include <stdexcept>
#include <vector>
#include <cstddef>

// Forward declaration
extern void ReportViolationAndExit(const std::wstring& message, const std::string& type, const std::string& details);

namespace {
    constexpr auto kVerificationInterval = std::chrono::seconds(5);

    bool GetModulePath(HMODULE module, std::wstring& path) {
        if (!module) return false;

        constexpr size_t kInitialCapacity = MAX_PATH;
        constexpr size_t kMaximumCapacity = 32768;
        std::vector<wchar_t> buffer(kInitialCapacity);

        while (buffer.size() <= kMaximumCapacity) {
            const DWORD capacity = static_cast<DWORD>(buffer.size());
            const DWORD length = GetModuleFileNameW(module, buffer.data(), capacity);
            if (length == 0) {
                return false;
            }

            // A return value equal to nSize indicates that the path may be truncated.
            if (length < capacity) {
                path.assign(buffer.data(), static_cast<size_t>(length));
                return !path.empty();
            }

            if (buffer.size() == kMaximumCapacity) {
                return false;
            }
            buffer.resize((std::min)(buffer.size() * 2, kMaximumCapacity));
        }

        return false;
    }

    bool IsCodeSection(const IMAGE_SECTION_HEADER& section) {
        const auto characteristics = section.Characteristics;
        return (characteristics & IMAGE_SCN_CNT_CODE) != 0 &&
               (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
    }

    bool IsReadableRange(const void* address, size_t length) {
        if (length == 0) return true;
        uintptr_t cursor = reinterpret_cast<uintptr_t>(address);
        if (cursor > (std::numeric_limits<uintptr_t>::max)() - length) return false;
        size_t remaining = length;

        while (remaining > 0) {
            MEMORY_BASIC_INFORMATION mbi{};
            if (VirtualQuery(reinterpret_cast<const void*>(cursor), &mbi, sizeof(mbi)) == 0 ||
                mbi.State != MEM_COMMIT || (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0) {
                return false;
            }

            const DWORD protection = mbi.Protect & 0xFF;
            const bool readable =
                protection == PAGE_READONLY ||
                protection == PAGE_READWRITE ||
                protection == PAGE_WRITECOPY ||
                protection == PAGE_EXECUTE_READ ||
                protection == PAGE_EXECUTE_READWRITE ||
                protection == PAGE_EXECUTE_WRITECOPY;
            if (!readable) return false;

            const uintptr_t regionBase = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
            if (regionBase > cursor ||
                mbi.RegionSize > (std::numeric_limits<uintptr_t>::max)() - regionBase) {
                return false;
            }
            const uintptr_t regionEnd = regionBase + mbi.RegionSize;
            if (regionEnd <= cursor) return false;

            const size_t available = static_cast<size_t>(regionEnd - cursor);
            const size_t step = (std::min)(remaining, available);
            cursor += step;
            remaining -= step;
        }
        return true;
    }

    bool GetDiskPeHeaders(const std::vector<uint8_t>& image,
                          const IMAGE_NT_HEADERS*& ntHeaders,
                          const IMAGE_SECTION_HEADER*& sectionHeaders,
                          size_t& sectionTableOffset) {
        ntHeaders = nullptr;
        sectionHeaders = nullptr;
        sectionTableOffset = 0;

        if (image.size() < sizeof(IMAGE_DOS_HEADER)) return false;
        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(image.data());
        if (dos->e_magic != IMAGE_DOS_SIGNATURE ||
            dos->e_lfanew < static_cast<LONG>(sizeof(IMAGE_DOS_HEADER))) {
            return false;
        }

        const size_t ntOffset = static_cast<size_t>(dos->e_lfanew);
        if (ntOffset > image.size() || sizeof(IMAGE_NT_HEADERS) > image.size() - ntOffset)
            return false;

        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(image.data() + ntOffset);
        if (nt->Signature != IMAGE_NT_SIGNATURE ||
            nt->FileHeader.NumberOfSections == 0 ||
            nt->FileHeader.NumberOfSections > 96 ||
            nt->FileHeader.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER) ||
#if defined(_WIN64)
            nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC
#else
            nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC
#endif
            ) {
            return false;
        }

        const size_t prefix = offsetof(IMAGE_NT_HEADERS, OptionalHeader);
        if (ntOffset > image.size() || prefix > image.size() - ntOffset)
            return false;
        const size_t optionalOffset = ntOffset + prefix;
        if (nt->FileHeader.SizeOfOptionalHeader > image.size() - optionalOffset)
            return false;

        sectionTableOffset = optionalOffset + nt->FileHeader.SizeOfOptionalHeader;
        const size_t sectionBytes =
            static_cast<size_t>(nt->FileHeader.NumberOfSections) * sizeof(IMAGE_SECTION_HEADER);
        if (sectionTableOffset > image.size() ||
            sectionBytes > image.size() - sectionTableOffset) {
            return false;
        }

        ntHeaders = nt;
        sectionHeaders = reinterpret_cast<const IMAGE_SECTION_HEADER*>(
            image.data() + sectionTableOffset);
        return true;
    }

    bool GetMappedPeHeaders(const uint8_t* base,
                            const IMAGE_NT_HEADERS*& ntHeaders,
                            const IMAGE_SECTION_HEADER*& sectionHeaders,
                            size_t& imageSize) {
        ntHeaders = nullptr;
        sectionHeaders = nullptr;
        imageSize = 0;
        if (!base || !IsReadableRange(base, sizeof(IMAGE_DOS_HEADER))) return false;

        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE ||
            dos->e_lfanew < static_cast<LONG>(sizeof(IMAGE_DOS_HEADER)) ||
            dos->e_lfanew > 1024 * 1024) {
            return false;
        }

        const size_t ntOffset = static_cast<size_t>(dos->e_lfanew);
        const uintptr_t baseAddress = reinterpret_cast<uintptr_t>(base);
        if (baseAddress > (std::numeric_limits<uintptr_t>::max)() - ntOffset)
            return false;
        const auto* ntAddress = reinterpret_cast<const uint8_t*>(baseAddress + ntOffset);
        if (!IsReadableRange(ntAddress, sizeof(IMAGE_NT_HEADERS))) return false;

        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(ntAddress);
        if (nt->Signature != IMAGE_NT_SIGNATURE ||
            nt->FileHeader.NumberOfSections == 0 ||
            nt->FileHeader.NumberOfSections > 96 ||
            nt->FileHeader.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER) ||
#if defined(_WIN64)
            nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC
#else
            nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC
#endif
            ) {
            return false;
        }

        imageSize = static_cast<size_t>(nt->OptionalHeader.SizeOfImage);
        if (imageSize < sizeof(IMAGE_DOS_HEADER) ||
            ntOffset > imageSize ||
            sizeof(IMAGE_NT_HEADERS) > imageSize - ntOffset) {
            return false;
        }

        const size_t prefix = offsetof(IMAGE_NT_HEADERS, OptionalHeader);
        if (ntOffset > imageSize || prefix > imageSize - ntOffset)
            return false;
        const size_t optionalOffset = ntOffset + prefix;
        if (nt->FileHeader.SizeOfOptionalHeader > imageSize - optionalOffset)
            return false;
        const size_t sectionOffset = optionalOffset + nt->FileHeader.SizeOfOptionalHeader;
        const size_t sectionBytes =
            static_cast<size_t>(nt->FileHeader.NumberOfSections) * sizeof(IMAGE_SECTION_HEADER);
        if (sectionOffset > imageSize || sectionBytes > imageSize - sectionOffset)
            return false;
        if (baseAddress > (std::numeric_limits<uintptr_t>::max)() - sectionOffset)
            return false;

        const auto* sections = reinterpret_cast<const IMAGE_SECTION_HEADER*>(
            base + sectionOffset);
        if (!IsReadableRange(sections, sectionBytes)) return false;

        ntHeaders = nt;
        sectionHeaders = sections;
        return true;
    }
}

namespace Oblivion {
    SelfIntegrityGuard::SelfIntegrityGuard(HMODULE moduleHandle)
        : m_module(moduleHandle),
          m_running(false) {
        GetModulePath(m_module, m_modulePath);
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

        m_running.store(true);
        try {
            m_worker = std::thread(&SelfIntegrityGuard::MonitoringLoop, this);
        } catch (...) {
            m_running.store(false);
            return false;
        }
        return true;
    }

    void SelfIntegrityGuard::Stop() {
        m_running.store(false);
        if (m_worker.joinable() &&
            m_worker.get_id() != std::this_thread::get_id()) {
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

        const std::streampos fileEnd = file.tellg();
        if (fileEnd <= std::streampos(0)) {
            return false;
        }

        const std::streamoff fileSize = static_cast<std::streamoff>(fileEnd);
        if (fileSize <= 0) {
            return false;
        }

        const std::uintmax_t unsignedFileSize =
            static_cast<std::uintmax_t>(fileSize);
        if (unsignedFileSize >
                static_cast<std::uintmax_t>((std::numeric_limits<size_t>::max)()) ||
            unsignedFileSize >
                static_cast<std::uintmax_t>((std::numeric_limits<std::streamsize>::max)())) {
            return false;
        }

        const size_t imageSize = static_cast<size_t>(fileSize);
        const std::streamsize readSize = static_cast<std::streamsize>(fileSize);
        std::vector<uint8_t> loadedImage;
        if (imageSize > loadedImage.max_size()) {
            return false;
        }

        try {
            loadedImage.resize(imageSize);
        } catch (const std::bad_alloc&) {
            return false;
        } catch (const std::length_error&) {
            return false;
        }

        file.seekg(0, std::ios::beg);
        if (!file) {
            return false;
        }

        file.read(reinterpret_cast<char*>(loadedImage.data()), readSize);
        if (!file || file.gcount() != readSize) {
            // Keep the member image empty; a later Start() must retry the read.
            return false;
        }

        // Publish only a complete image. A partial read is discarded with the
        // local temporary instead of leaving a non-empty member that looks loaded.
        m_diskImage.swap(loadedImage);
        return true;
    }

    void SelfIntegrityGuard::MonitoringLoop() {
        while (m_running.load()) {
            if (!VerifySectionsOnce()) {
                // Every failed verification path is reported before returning.
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
        const auto* moduleBase = reinterpret_cast<const uint8_t*>(m_module);
        const IMAGE_NT_HEADERS* memoryNt = nullptr;
        const IMAGE_SECTION_HEADER* memorySections = nullptr;
        size_t imageSize = 0;
        if (!GetMappedPeHeaders(moduleBase, memoryNt, memorySections, imageSize)) {
            ReportViolationAndExit(L"", "SELF_INTEGRITY_UNAVAILABLE",
                                   "Mapped PE headers could not be read during self-integrity verification");
            return false;
        }

        const IMAGE_NT_HEADERS* diskNt = nullptr;
        const IMAGE_SECTION_HEADER* diskSections = nullptr;
        size_t diskSectionOffset = 0;
        if (!GetDiskPeHeaders(m_diskImage, diskNt, diskSections, diskSectionOffset)) {
            ReportViolationAndExit(L"", "SELF_INTEGRITY_UNAVAILABLE",
                                   "Disk PE headers could not be read during self-integrity verification");
            return false;
        }

        if (memoryNt->FileHeader.NumberOfSections != diskNt->FileHeader.NumberOfSections ||
            memoryNt->FileHeader.Machine != diskNt->FileHeader.Machine ||
            memoryNt->OptionalHeader.SizeOfImage != diskNt->OptionalHeader.SizeOfImage) {
            ReportTamper("PE_HEADERS");
            return false;
        }

        const WORD sectionCount = diskNt->FileHeader.NumberOfSections;
        for (WORD i = 0; i < sectionCount; ++i) {
            const IMAGE_SECTION_HEADER& memorySection = memorySections[i];
            const IMAGE_SECTION_HEADER& diskSection = diskSections[i];

            if (std::memcmp(memorySection.Name, diskSection.Name, IMAGE_SIZEOF_SHORT_NAME) != 0 ||
                memorySection.VirtualAddress != diskSection.VirtualAddress ||
                memorySection.Misc.VirtualSize != diskSection.Misc.VirtualSize ||
                memorySection.SizeOfRawData != diskSection.SizeOfRawData ||
                memorySection.PointerToRawData != diskSection.PointerToRawData ||
                memorySection.Characteristics != diskSection.Characteristics) {
                size_t nameLength = 0;
                while (nameLength < IMAGE_SIZEOF_SHORT_NAME && diskSection.Name[nameLength] != 0)
                    ++nameLength;
                ReportTamper(std::string(reinterpret_cast<const char*>(diskSection.Name), nameLength));
                return false;
            }

            if (!IsCodeSection(diskSection)) continue;

            size_t nameLength = 0;
            while (nameLength < IMAGE_SIZEOF_SHORT_NAME && diskSection.Name[nameLength] != 0)
                ++nameLength;
            const std::string sectionName(
                reinterpret_cast<const char*>(diskSection.Name), nameLength);

            const SectionCompareResult comparison = CompareSection(diskSection);
            if (comparison == SectionCompareResult::Incomplete) {
                ReportViolationAndExit(
                    L"", "SELF_INTEGRITY_UNAVAILABLE",
                    "Unable to inspect executable code section " + sectionName +
                        " during self-integrity verification");
                return false;
            }
            if (comparison == SectionCompareResult::Mismatch) {
                ReportTamper(sectionName);
                return false;
            }
        }

        return true;
    }

    SelfIntegrityGuard::SectionCompareResult
    SelfIntegrityGuard::CompareSection(const IMAGE_SECTION_HEADER& section) const {
        const auto* moduleBase = reinterpret_cast<const uint8_t*>(m_module);
        const IMAGE_NT_HEADERS* memoryNt = nullptr;
        const IMAGE_SECTION_HEADER* memorySections = nullptr;
        size_t imageSize = 0;
        if (!GetMappedPeHeaders(moduleBase, memoryNt, memorySections, imageSize))
            return SectionCompareResult::Incomplete;
        (void)memoryNt;
        (void)memorySections;

        // VirtualSize is the mapped extent. Bytes beyond SizeOfRawData are
        // zero-filled by the PE loader; bytes beyond VirtualSize are not part
        // of this section even when the file stores alignment padding.
        const size_t rawSize = static_cast<size_t>(section.SizeOfRawData);
        const size_t virtualSize = static_cast<size_t>(section.Misc.VirtualSize);
        const size_t mappedSize = virtualSize != 0 ? virtualSize : rawSize;
        if (mappedSize == 0) return SectionCompareResult::Match;

        const size_t fileBackedSize = (std::min)(mappedSize, rawSize);
        const size_t sectionRva = static_cast<size_t>(section.VirtualAddress);
        if (sectionRva > imageSize || mappedSize > imageSize - sectionRva)
            return SectionCompareResult::Incomplete;

        const size_t rawOffset = static_cast<size_t>(section.PointerToRawData);
        if (fileBackedSize > 0 &&
            (rawOffset > m_diskImage.size() ||
             fileBackedSize > m_diskImage.size() - rawOffset)) {
            return SectionCompareResult::Incomplete;
        }

        const auto* sectionMemory = moduleBase + sectionRva;
        if (!IsReadableRange(sectionMemory, mappedSize))
            return SectionCompareResult::Incomplete;

        const uint8_t* sectionOnDisk = fileBackedSize > 0
            ? m_diskImage.data() + rawOffset
            : nullptr;

        const size_t maximumRva =
            static_cast<size_t>((std::numeric_limits<DWORD>::max)());
        if (mappedSize > maximumRva ||
            sectionRva > maximumRva - mappedSize) {
            return SectionCompareResult::Incomplete;
        }
        const DWORD sectionStartRva = section.VirtualAddress;
        const DWORD sectionEndRva =
            sectionStartRva + static_cast<DWORD>(mappedSize);

        std::vector<std::pair<size_t, size_t>> skipIntervals;
        BuildSkipIntervals(sectionStartRva, sectionEndRva, skipIntervals);

        const auto rangeMatches = [&](size_t begin, size_t end) {
            if (begin > end || end > mappedSize) return false;

            // Compare the file-backed part against the exact raw-file offset.
            const size_t diskEnd = (std::min)(end, fileBackedSize);
            if (begin < diskEnd &&
                std::memcmp(sectionMemory + begin, sectionOnDisk + begin,
                            diskEnd - begin) != 0) {
                return false;
            }

            // The loader zero-fills the virtual tail when VirtualSize is
            // larger than SizeOfRawData. Any nonzero byte here is a mismatch.
            const size_t zeroStart = (std::max)(begin, fileBackedSize);
            for (size_t offset = zeroStart; offset < end; ++offset) {
                if (sectionMemory[offset] != 0) return false;
            }
            return true;
        };

        size_t currentOffset = 0;
        for (const auto& interval : skipIntervals) {
            const size_t intervalStart = interval.first;
            const size_t intervalEnd = interval.second;
            if (intervalStart > mappedSize ||
                intervalEnd > mappedSize ||
                intervalStart > intervalEnd) {
                return SectionCompareResult::Incomplete;
            }

            if (currentOffset < intervalStart &&
                !rangeMatches(currentOffset, intervalStart)) {
                return SectionCompareResult::Mismatch;
            }
            currentOffset = (std::max)(currentOffset, intervalEnd);
        }

        if (currentOffset < mappedSize &&
            !rangeMatches(currentOffset, mappedSize)) {
            return SectionCompareResult::Mismatch;
        }

        return SectionCompareResult::Match;
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

        const IMAGE_NT_HEADERS* ntHeaders = nullptr;
        const IMAGE_SECTION_HEADER* sectionHeaders = nullptr;
        size_t sectionTableOffset = 0;
        if (!GetDiskPeHeaders(m_diskImage, ntHeaders, sectionHeaders, sectionTableOffset))
            return false;

        if (ntHeaders->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_BASERELOC)
            return true;

        const auto& relocDirectory =
            ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (relocDirectory.VirtualAddress == 0 && relocDirectory.Size == 0) return true;
        if (relocDirectory.VirtualAddress == 0 || relocDirectory.Size == 0) return false;

        DWORD relocFileOffset = 0;
        if (!RvaToFileRange(relocDirectory.VirtualAddress, relocDirectory.Size, relocFileOffset))
            return false;

        size_t remaining = relocDirectory.Size;
        const uint8_t* cursor = m_diskImage.data() + relocFileOffset;
        const DWORD imageSize = ntHeaders->OptionalHeader.SizeOfImage;

        while (remaining > 0) {
            if (remaining < sizeof(IMAGE_BASE_RELOCATION)) return false;
            const auto* block = reinterpret_cast<const IMAGE_BASE_RELOCATION*>(cursor);
            if (block->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION) ||
                block->SizeOfBlock > remaining ||
                ((block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) % sizeof(WORD)) != 0) {
                return false;
            }

            const size_t entryCount =
                (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            const auto* entries =
                reinterpret_cast<const WORD*>(cursor + sizeof(IMAGE_BASE_RELOCATION));

            for (size_t i = 0; i < entryCount; ++i) {
                const WORD typeOffset = entries[i];
                const WORD type = typeOffset >> 12;
                const WORD offset = typeOffset & 0x0FFF;

                size_t spanSize = 0;
                switch (type) {
                case IMAGE_REL_BASED_ABSOLUTE:
                    // Padding entry; it does not describe a relocated address.
                    continue;
                case IMAGE_REL_BASED_HIGH:
                case IMAGE_REL_BASED_LOW:
                    spanSize = sizeof(WORD);
                    break;
                case IMAGE_REL_BASED_HIGHLOW:
                    spanSize = sizeof(DWORD);
                    break;
                case IMAGE_REL_BASED_HIGHADJ:
                    // HIGHADJ consumes the following WORD as the low part of
                    // its signed addend. It is not a second relocation entry.
                    if (i + 1 >= entryCount) return false;
                    ++i;
                    spanSize = sizeof(WORD);
                    break;
                case IMAGE_REL_BASED_DIR64:
                    spanSize = sizeof(ULONGLONG);
                    break;
                default:
                    // Unknown relocation types cannot safely be ignored: their
                    // loader-written bytes would otherwise be misclassified as
                    // tampering during the disk-vs-memory comparison.
                    return false;
                }

                if (block->VirtualAddress > imageSize ||
                    offset > imageSize - block->VirtualAddress) return false;
                const DWORD rva = block->VirtualAddress + offset;
                if (rva > imageSize || spanSize > imageSize - rva) return false;
                m_relocationSpans.push_back({ rva, spanSize });
            }

            cursor += block->SizeOfBlock;
            remaining -= block->SizeOfBlock;
        }

        std::sort(m_relocationSpans.begin(), m_relocationSpans.end(),
            [](const RelocationSpan& a, const RelocationSpan& b) { return a.rva < b.rva; });
        return true;
    }

    bool SelfIntegrityGuard::RvaToFileRange(DWORD rva, DWORD size, DWORD& fileOffset) const {
        fileOffset = 0;
        if (size == 0) return false;

        const IMAGE_NT_HEADERS* ntHeaders = nullptr;
        const IMAGE_SECTION_HEADER* sectionHeaders = nullptr;
        size_t sectionTableOffset = 0;
        if (!GetDiskPeHeaders(m_diskImage, ntHeaders, sectionHeaders, sectionTableOffset))
            return false;

        const size_t imageSize = ntHeaders->OptionalHeader.SizeOfImage;
        if (static_cast<size_t>(rva) > imageSize ||
            static_cast<size_t>(size) > imageSize - static_cast<size_t>(rva)) {
            return false;
        }

        for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i) {
            const IMAGE_SECTION_HEADER& section = sectionHeaders[i];
            const size_t sectionStart = static_cast<size_t>(section.VirtualAddress);
            const size_t sectionSize = (std::max)(
                static_cast<size_t>(section.Misc.VirtualSize),
                static_cast<size_t>(section.SizeOfRawData));
            if (sectionStart > imageSize || sectionSize > imageSize - sectionStart)
                return false;

            const size_t requestStart = static_cast<size_t>(rva);
            if (requestStart < sectionStart || requestStart >= sectionStart + sectionSize)
                continue;

            const size_t offsetWithinSection = requestStart - sectionStart;
            if (offsetWithinSection > section.SizeOfRawData ||
                static_cast<size_t>(size) > static_cast<size_t>(section.SizeOfRawData) - offsetWithinSection)
                return false;

            const size_t rawOffset = static_cast<size_t>(section.PointerToRawData);
            if (rawOffset > m_diskImage.size() ||
                offsetWithinSection > m_diskImage.size() - rawOffset ||
                static_cast<size_t>(size) > m_diskImage.size() - rawOffset - offsetWithinSection)
                return false;

            const size_t finalOffset = rawOffset + offsetWithinSection;
            if (finalOffset > (std::numeric_limits<DWORD>::max)()) return false;
            fileOffset = static_cast<DWORD>(finalOffset);
            return true;
        }

        if (static_cast<size_t>(rva) < ntHeaders->OptionalHeader.SizeOfHeaders &&
            static_cast<size_t>(size) <=
                static_cast<size_t>(ntHeaders->OptionalHeader.SizeOfHeaders) - rva &&
            static_cast<size_t>(rva) <= m_diskImage.size() &&
            static_cast<size_t>(size) <= m_diskImage.size() - rva) {
            fileOffset = rva;
            return true;
        }

        return false;
    }

    void SelfIntegrityGuard::BuildSkipIntervals(DWORD sectionStart, DWORD sectionEnd,
                                                   std::vector<std::pair<size_t, size_t>>& skips) const {
        skips.clear();
        if (sectionStart >= sectionEnd) return;

        for (const auto& span : m_relocationSpans) {
            if (span.size == 0 ||
                span.size > static_cast<size_t>((std::numeric_limits<DWORD>::max)() - span.rva)) {
                continue;
            }

            const DWORD spanStart = span.rva;
            const DWORD spanEnd = spanStart + static_cast<DWORD>(span.size);
            if (spanEnd <= sectionStart || spanStart >= sectionEnd) continue;

            const size_t relativeStart =
                static_cast<size_t>((std::max)(spanStart, sectionStart) - sectionStart);
            const size_t relativeEnd =
                static_cast<size_t>((std::min)(spanEnd, sectionEnd) - sectionStart);
            if (relativeStart < relativeEnd) skips.emplace_back(relativeStart, relativeEnd);
        }

        if (skips.empty()) return;
        std::sort(skips.begin(), skips.end());

        std::vector<std::pair<size_t, size_t>> merged;
        merged.reserve(skips.size());
        auto current = skips.front();
        for (size_t i = 1; i < skips.size(); ++i) {
            const auto& interval = skips[i];
            if (interval.first <= current.second)
                current.second = (std::max)(current.second, interval.second);
            else {
                merged.push_back(current);
                current = interval;
            }
        }
        merged.push_back(current);
        skips.swap(merged);
    }
}

