#pragma once

#include <windows.h>
#include <vector>
#include <string>
#include <cstdint>
#include <fstream>
#include <map>
#include <unordered_set>

namespace Oblivion {
    // Struktur untuk menyimpan baseline yang diverifikasi dari disk
    struct ExecutableRegion {
        uintptr_t rva;              // Relative Virtual Address (offset dari base)
        size_t size;                // Ukuran region dalam bytes
        uint32_t diskCRC32;         // CRC32 dari file di disk (ground truth)
        uint32_t memoryCRC32;       // CRC32 dari memori saat pertama load (untuk cross-check)
        bool isCodeSection;         // Apakah ini code section (.text)
    };

    // Struktur untuk PE section header info
    struct PESectionInfo {
        std::string name{};
        uint32_t virtualAddress{0};
        uint32_t virtualSize{0};
        uint32_t rawDataOffset{0};
        uint32_t rawDataSize{0};
        uint32_t characteristics{0};
    };

    // Embedded signature (diisi saat build-time)
    struct EmbeddedSignature {
        uint32_t magicNumber;       // Magic number untuk validasi
        uint32_t textSectionHash;   // SHA256 hash dari .text section (first 32 bits)
        uint32_t rdataSectionHash;  // SHA256 hash dari .rdata section
        uint32_t buildTimestamp;    // Timestamp saat build
        uint32_t imageSize;         // Total size dari PE image
        uint32_t checksum;          // Checksum untuk memverifikasi signature ini
    };

    class MemoryScanner {
    public:
        MemoryScanner();
        ~MemoryScanner();

        // Fungsi utama untuk memindai memori
        void PerformScan();

    private:
        // === LAYER 1: PE Header & Structure Validation ===
        bool ValidatePEStructure(const std::vector<uint8_t>& fileData);
        bool ParsePEHeaders(const std::vector<uint8_t>& fileData, 
                          std::vector<PESectionInfo>& sections);
        bool ValidateImageHeaders(const std::vector<uint8_t>& fileData,
                                 IMAGE_DOS_HEADER& dosHeader,
                                 IMAGE_NT_HEADERS& ntHeaders);
        
        // === LAYER 2: Disk-Based Baseline Creation ===
        bool ReadExecutableFile(const std::wstring& filePath, std::vector<uint8_t>& fileData);
        void CreateBaselineFromDisk(const std::wstring& filePath);
        uint32_t CalculateSectionHashFromDisk(const std::vector<uint8_t>& fileData,
                                             const PESectionInfo& section);
        
        // === LAYER 3: Embedded Signature Verification ===
        bool VerifyEmbeddedSignature(const std::vector<uint8_t>& fileData);
        bool ExtractEmbeddedSignature(const std::vector<uint8_t>& fileData,
                                     EmbeddedSignature& signature);
        uint32_t CalculateSignatureChecksum(const EmbeddedSignature& sig);
        
        // === LAYER 4: Cross-Verification (Disk vs Memory) ===
        bool CrossVerifyDiskAndMemory(const std::vector<uint8_t>& fileData);
        bool CompareCodeSections(const std::vector<uint8_t>& diskData,
                                const uint8_t* memoryBase,
                                const PESectionInfo& section);
        
        // === LAYER 5: Runtime Integrity Verification ===
        bool VerifyRegionIntegrity(uint8_t* memoryBase, size_t regionSize, uintptr_t rva);
        bool DetectSuspiciousMemoryRegion(uint8_t* memoryBase, size_t regionSize);
        bool DetectCodeCaveInjection(const uint8_t* codeSection, size_t size);
        
        // === Cryptographic Functions ===
        uint32_t CalculateCRC32(const uint8_t* data, size_t size);
        uint64_t CalculateSHA256_32bit(const uint8_t* data, size_t size);
        
        // === Anti-Tampering Detection ===
        bool DetectBaselineModification();
        bool VerifyBaselineIntegrity();
        uint32_t CalculateBaselineChecksum();

        // === Helpers ===
        const PESectionInfo* GetSectionByRva(uintptr_t rva) const;
        bool IsJITRuntimePresent() const;
        bool IsSystemModule(const std::wstring& modulePath) const;
        bool IsSectionVerified(uint32_t sectionRva) const;

        // === Member Variables ===
        std::vector<ExecutableRegion> m_diskBaseline;      // Baseline dari disk (trusted)
        std::map<uint32_t, PESectionInfo> m_sectionMap;    // Map RVA -> Section Info
        std::unordered_set<uint32_t> m_verifiedSections;   // Sections yang terakhir diverifikasi
        EmbeddedSignature m_embeddedSig;                   // Embedded signature
        uintptr_t m_moduleBaseAddress;                     // Base address modul
        bool m_baselineCreated;                            // Flag baseline creation
        bool m_baselineVerified;                           // Flag baseline verification
        uint32_t m_baselineChecksum;                       // Checksum untuk baseline integrity
        std::wstring m_executablePath;                     // Path ke executable
    };
}