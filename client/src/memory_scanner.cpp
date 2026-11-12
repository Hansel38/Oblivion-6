#include "pch.h"
#include "memory_scanner.h"
#include <tlhelp32.h>
#include <iostream>
#include <iomanip>
#include <string>
#include <fstream>
#include <algorithm>
#include <wincrypt.h>
#include <sstream>

#pragma comment(lib, "crypt32.lib")

// Forward declaration
extern void ReportViolationAndExit(const std::wstring& message, const std::string& type, const std::string& details);

// CRITICAL: Baseline dibuat dari DISK, bukan dari memori yang mungkin sudah terinfeksi
// Multi-layer verification:
// 1. PE structure validation
// 2. Embedded signature verification (build-time)
// 3. Disk-based baseline creation
// 4. Cross-verification (disk vs memory)
// 5. Runtime integrity monitoring

namespace Oblivion {
    MemoryScanner::MemoryScanner() 
        : m_baselineCreated(false)
        , m_baselineVerified(false)
        , m_moduleBaseAddress(0)
        , m_baselineChecksum(0) 
    {
        ZeroMemory(&m_embeddedSig, sizeof(m_embeddedSig));
    }

    MemoryScanner::~MemoryScanner() {}

    // === Cryptographic Hash Functions ===
    
    uint32_t MemoryScanner::CalculateCRC32(const uint8_t* data, size_t size) {
        // Tabel CRC32 lookup (polynomial 0xEDB88320)
        static const uint32_t crc32_table[256] = {
            0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA, 0x076DC419, 0x706AF48F,
            0xE963A535, 0x9E6495A3, 0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988,
            0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91, 0x1DB71064, 0x6AB020F2,
            0xF3B97148, 0x84BE41DE, 0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,
            0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC, 0x14015C4F, 0x63066CD9,
            0xFA0F3D63, 0x8D080DF5, 0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172,
            0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B, 0x35B5A8FA, 0x42B2986C,
            0xDBBBC9D6, 0xACBCF940, 0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59,
            0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116, 0x21B4F4B5, 0x56B3C423,
            0xCFBA9599, 0xB8BDA50F, 0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924,
            0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D, 0x76DC4190, 0x01DB7106,
            0x98D220BC, 0xEFD5102A, 0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433,
            0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818, 0x7F6A0DBB, 0x086D3D2D,
            0x91646C97, 0xE6635C01, 0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E,
            0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457, 0x65B0D9C6, 0x12B7E950,
            0x8BBEB8EA, 0xFCB9887C, 0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
            0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2, 0x4ADFA541, 0x3DD895D7,
            0xA4D1C46D, 0xD3D6F4FB, 0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0,
            0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9, 0x5005713C, 0x270241AA,
            0xBE0B1010, 0xC90C2086, 0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F,
            0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4, 0x59B33D17, 0x2EB40D81,
            0xB7BD5C3B, 0xC0BA6CAD, 0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A,
            0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683, 0xE3630B12, 0x94643B84,
            0x0D6D6A3E, 0x7A6A5AA8, 0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1,
            0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE, 0xF762575D, 0x806567CB,
            0x196C3671, 0x6E6B06E7, 0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC,
            0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5, 0xD6D6A3E8, 0xA1D1937E,
            0x38D8C2C4, 0x4FDFF252, 0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
            0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60, 0xDF60EFC3, 0xA867DF55,
            0x316E8EEF, 0x4669BE79, 0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236,
            0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F, 0xC5BA3BBE, 0xB2BD0B28,
            0x2BB45A92, 0x5CB36A04, 0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D,
            0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A, 0x9C0906A9, 0xEB0E363F,
            0x72076785, 0x05005713, 0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38,
            0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21, 0x86D3D2D4, 0xF1D4E242,
            0x68DDB3F8, 0x1FDA836E, 0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777,
            0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C, 0x8F659EFF, 0xF862AE69,
            0x616BFFD3, 0x166CCF45, 0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2,
            0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB, 0xAED16A4A, 0xD9D65ADC,
            0x40DF0B66, 0x37D83BF0, 0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9,
            0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6, 0xBAD03605, 0xCDD70693,
            0x54DE5729, 0x23D967BF, 0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94,
            0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D
        };

        uint32_t crc = 0xFFFFFFFF;
        for (size_t i = 0; i < size; ++i) {
            crc = (crc >> 8) ^ crc32_table[(crc ^ data[i]) & 0xFF];
        }
        return crc ^ 0xFFFFFFFF;
    }

    // Simplified SHA256 implementation (32-bit truncated untuk efficiency)
    // Menggunakan Windows CryptoAPI untuk reliability
    uint64_t MemoryScanner::CalculateSHA256_32bit(const uint8_t* data, size_t size) {
        HCRYPTPROV hProv = 0;
        HCRYPTHASH hHash = 0;
        BYTE hash[32];
        DWORD hashLen = 32;
        uint64_t result = 0;

        if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
            return 0;
        }

        if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
            CryptReleaseContext(hProv, 0);
            return 0;
        }

        if (!CryptHashData(hHash, data, static_cast<DWORD>(size), 0)) {
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            return 0;
        }

        if (!CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0)) {
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            return 0;
        }

        // Ambil 64-bit pertama dari SHA256
        result = *reinterpret_cast<uint64_t*>(hash);

        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);

        return result;
    }

    // === LAYER 1: PE Structure Validation ===\n    
    bool MemoryScanner::ReadExecutableFile(const std::wstring& filePath, std::vector<uint8_t>& fileData) {
        std::ifstream file(filePath, std::ios::binary | std::ios::ate);
        if (!file.is_open()) {
            return false;
        }

        std::streamsize size = file.tellg();
        file.seekg(0, std::ios::beg);

        fileData.resize(static_cast<size_t>(size));
        if (!file.read(reinterpret_cast<char*>(fileData.data()), size)) {
            return false;
        }

        return true;
    }

    // Helper: Temukan section berdasarkan RVA
    const PESectionInfo* MemoryScanner::GetSectionByRva(uintptr_t rva) const {
        // m_sectionMap keyed by section.virtualAddress (section RVA start)
        // Cari section yang mengandung RVA
        for (const auto& kv : m_sectionMap) {
            const PESectionInfo& sec = kv.second;
            uintptr_t start = static_cast<uintptr_t>(sec.virtualAddress);
            uintptr_t end = start + static_cast<uintptr_t>(sec.virtualSize);
            if (rva >= start && rva < end) {
                return &sec;
            }
        }
        return nullptr;
    }

    bool MemoryScanner::IsSectionVerified(uint32_t sectionRva) const {
        return m_verifiedSections.find(sectionRva) != m_verifiedSections.end();
    }

    // Helper: Deteksi kehadiran runtime JIT umum yang kadang membuat halaman RWX secara sah
    bool MemoryScanner::IsJITRuntimePresent() const {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            return false;
        }

        MODULEENTRY32W me32;
        me32.dwSize = sizeof(MODULEENTRY32W);

        const wchar_t* jitModules[] = {
            L"clrjit.dll", L"coreclr.dll", L"mscorlib.dll",
            L"chakra.dll", L"jscript9.dll", L"v8.dll",
            L"luajit.dll"
        };

        bool present = false;
        if (Module32FirstW(hSnapshot, &me32)) {
            do {
                for (const auto& name : jitModules) {
                    if (_wcsicmp(me32.szModule, name) == 0) {
                        present = true;
                        break;
                    }
                }
                if (present) break;
            } while (Module32NextW(hSnapshot, &me32));
        }

        CloseHandle(hSnapshot);
        return present;
    }

    // Helper: Cek apakah modul berasal dari System32 atau SysWOW64 (modul Windows sah)
    bool MemoryScanner::IsSystemModule(const std::wstring& modulePath) const {
        std::wstring pathLower = modulePath;
        std::transform(pathLower.begin(), pathLower.end(), pathLower.begin(), ::towlower);

        // Cek apakah path mengandung system32 atau syswow64
        if (pathLower.find(L"\\system32\\") != std::wstring::npos ||
            pathLower.find(L"\\syswow64\\") != std::wstring::npos ||
            pathLower.find(L"\\windows\\") != std::wstring::npos) {
            return true;
        }

        return false;
    }

    bool MemoryScanner::ValidateImageHeaders(const std::vector<uint8_t>& fileData,
                                             IMAGE_DOS_HEADER& dosHeader,
                                             IMAGE_NT_HEADERS& ntHeaders) {
        if (fileData.size() < sizeof(IMAGE_DOS_HEADER)) {
            return false;
        }

        // Validate DOS header
        dosHeader = *reinterpret_cast<const IMAGE_DOS_HEADER*>(fileData.data());
        if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
            return false;
        }

        // Validate NT headers offset
        if (static_cast<size_t>(dosHeader.e_lfanew) >= fileData.size() - sizeof(IMAGE_NT_HEADERS)) {
            return false;
        }

        // Validate NT headers
        ntHeaders = *reinterpret_cast<const IMAGE_NT_HEADERS*>(fileData.data() + dosHeader.e_lfanew);
        if (ntHeaders.Signature != IMAGE_NT_SIGNATURE) {
            return false;
        }

        // Validate machine type (x86 or x64)
        if (ntHeaders.FileHeader.Machine != IMAGE_FILE_MACHINE_I386 &&
            ntHeaders.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
            return false;
        }

        return true;
    }

    bool MemoryScanner::ParsePEHeaders(const std::vector<uint8_t>& fileData, 
                                       std::vector<PESectionInfo>& sections) {
        IMAGE_DOS_HEADER dosHeader;
        IMAGE_NT_HEADERS ntHeaders;

        if (!ValidateImageHeaders(fileData, dosHeader, ntHeaders)) {
            return false;
        }

        // Parse section headers
        DWORD sectionOffset = dosHeader.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + 
                             ntHeaders.FileHeader.SizeOfOptionalHeader;

        for (WORD i = 0; i < ntHeaders.FileHeader.NumberOfSections; i++) {
            if (sectionOffset + sizeof(IMAGE_SECTION_HEADER) > fileData.size()) {
                break;
            }

            const IMAGE_SECTION_HEADER* sectionHeader = 
                reinterpret_cast<const IMAGE_SECTION_HEADER*>(fileData.data() + sectionOffset);

            PESectionInfo section;
            section.name = std::string(reinterpret_cast<const char*>(sectionHeader->Name), 
                                      strnlen(reinterpret_cast<const char*>(sectionHeader->Name), 8));
            section.virtualAddress = sectionHeader->VirtualAddress;
            section.virtualSize = sectionHeader->Misc.VirtualSize;
            section.rawDataOffset = sectionHeader->PointerToRawData;
            section.rawDataSize = sectionHeader->SizeOfRawData;
            section.characteristics = sectionHeader->Characteristics;

            sections.push_back(section);
            m_sectionMap[section.virtualAddress] = section;

            sectionOffset += sizeof(IMAGE_SECTION_HEADER);
        }

        return !sections.empty();
    }

    bool MemoryScanner::ValidatePEStructure(const std::vector<uint8_t>& fileData) {
        std::vector<PESectionInfo> sections;
        
        if (!ParsePEHeaders(fileData, sections)) {
            std::string details = "PE structure validation failed: Invalid headers or corrupted file";
            ReportViolationAndExit(L"", "PE_VALIDATION_FAILED", details);
            return false;
        }

        // Verify critical sections exist
        bool hasTextSection = false;
        bool hasDataSection = false;

        for (const auto& section : sections) {
            if (section.name.find(".text") != std::string::npos) {
                hasTextSection = true;
            }
            if (section.name.find(".data") != std::string::npos || 
                section.name.find(".rdata") != std::string::npos) {
                hasDataSection = true;
            }
        }

        if (!hasTextSection) {
            std::string details = "PE validation failed: Missing .text section";
            ReportViolationAndExit(L"", "MISSING_TEXT_SECTION", details);
            return false;
        }

        return true;
    }

    // === LAYER 2 & 3: Embedded Signature + Disk-Based Baseline ===

    uint32_t MemoryScanner::CalculateSignatureChecksum(const EmbeddedSignature& sig) {
        // Calculate checksum dari semua field kecuali checksum itu sendiri
        uint32_t data[] = {
            sig.magicNumber,
            sig.textSectionHash,
            sig.rdataSectionHash,
            sig.buildTimestamp,
            sig.imageSize
        };
        return CalculateCRC32(reinterpret_cast<const uint8_t*>(data), sizeof(data));
    }

    bool MemoryScanner::ExtractEmbeddedSignature(const std::vector<uint8_t>& fileData,
                                                 EmbeddedSignature& signature) {
        // CATATAN: Dalam implementasi real, signature harus di-embed saat build-time
        // oleh build system (post-build script) di section khusus seperti .rsrc atau .oblivion
        // Untuk sekarang, kita cari di akhir .rdata section atau section khusus
        
        std::vector<PESectionInfo> sections;
        if (!ParsePEHeaders(fileData, sections)) {
            return false;
        }

        // Cari section .oblivion atau .rdata
        for (const auto& section : sections) {
            if (section.name == ".oblivion" || section.name == ".rdata") {
                size_t searchStart = section.rawDataOffset + section.rawDataSize - sizeof(EmbeddedSignature) - 256;
                size_t searchEnd = section.rawDataOffset + section.rawDataSize;

                if (searchStart >= fileData.size()) continue;

                // Cari magic number
                for (size_t i = searchStart; i < searchEnd - sizeof(EmbeddedSignature); i++) {
                    const EmbeddedSignature* potential = 
                        reinterpret_cast<const EmbeddedSignature*>(fileData.data() + i);

                    // Magic number untuk Oblivion: 0x4F424C56 ('OBLV')
                    if (potential->magicNumber == 0x4F424C56) {
                        // Verify checksum
                        uint32_t calculatedChecksum = CalculateSignatureChecksum(*potential);
                        if (calculatedChecksum == potential->checksum) {
                            signature = *potential;
                            return true;
                        }
                    }
                }
            }
        }

        return false;
    }

    bool MemoryScanner::VerifyEmbeddedSignature(const std::vector<uint8_t>& fileData) {
        EmbeddedSignature signature;
        
        if (!ExtractEmbeddedSignature(fileData, signature)) {
            // Signature tidak ditemukan - mungkin belum di-embed saat build
            // Untuk development, kita skip verifikasi ini
            // Untuk production, ini harus CRITICAL ERROR
            #ifdef OBLIVION_RELEASE
            std::string details = "Embedded signature not found or invalid - possible tampering";
            ReportViolationAndExit(L"", "SIGNATURE_MISSING", details);
            return false;
            #else
            return true; // Skip untuk debug builds
            #endif
        }

        m_embeddedSig = signature;

        // Verify signature data matches actual file
        std::vector<PESectionInfo> sections;
        if (!ParsePEHeaders(fileData, sections)) {
            return false;
        }

        // Find .text section dan verify hash
        for (const auto& section : sections) {
            if (section.name.find(".text") != std::string::npos) {
                if (section.rawDataOffset + section.rawDataSize > fileData.size()) {
                    continue;
                }

                uint64_t textHash = CalculateSHA256_32bit(
                    fileData.data() + section.rawDataOffset,
                    section.rawDataSize
                );

                // Compare dengan embedded signature (gunakan 32-bit pertama)
                if (static_cast<uint32_t>(textHash) != signature.textSectionHash) {
                    std::string details = "Text section hash mismatch - file has been modified";
                    ReportViolationAndExit(L"", "SIGNATURE_MISMATCH", details);
                    return false;
                }

                break;
            }
        }

        return true;
    }

    uint32_t MemoryScanner::CalculateSectionHashFromDisk(const std::vector<uint8_t>& fileData,
                                                         const PESectionInfo& section) {
        if (section.rawDataOffset + section.rawDataSize > fileData.size()) {
            return 0;
        }

        return CalculateCRC32(
            fileData.data() + section.rawDataOffset,
            section.rawDataSize
        );
    }

    void MemoryScanner::CreateBaselineFromDisk(const std::wstring& filePath) {
        if (m_baselineCreated) {
            return;
        }

        m_executablePath = filePath;

        // STEP 1: Read file from disk
        std::vector<uint8_t> fileData;
        if (!ReadExecutableFile(filePath, fileData)) {
            std::string details = "Failed to read executable from disk";
            ReportViolationAndExit(L"", "BASELINE_READ_FAILED", details);
            return;
        }

        // STEP 2: Validate PE structure
        if (!ValidatePEStructure(fileData)) {
            return; // Error already reported
        }

        // STEP 3: Verify embedded signature (jika ada)
        VerifyEmbeddedSignature(fileData);

        // STEP 4: Parse sections and create disk-based baseline
        std::vector<PESectionInfo> sections;
        if (!ParsePEHeaders(fileData, sections)) {
            std::string details = "Failed to parse PE sections";
            ReportViolationAndExit(L"", "PE_PARSE_FAILED", details);
            return;
        }

        // STEP 5: Get module base address from memory
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            std::string details = "Failed to enumerate modules";
            ReportViolationAndExit(L"", "MODULE_ENUM_FAILED", details);
            return;
        }

        MODULEENTRY32W me32;
        me32.dwSize = sizeof(MODULEENTRY32W);

        if (Module32FirstW(hSnapshot, &me32)) {
            do {
                if (_wcsicmp(me32.szExePath, filePath.c_str()) == 0) {
                    m_moduleBaseAddress = reinterpret_cast<uintptr_t>(me32.modBaseAddr);
                    break;
                }
            } while (Module32NextW(hSnapshot, &me32));
        }

        CloseHandle(hSnapshot);

        if (m_moduleBaseAddress == 0) {
            std::string details = "Failed to find module base address";
            ReportViolationAndExit(L"", "MODULE_BASE_NOT_FOUND", details);
            return;
        }

        // STEP 6: Create baseline untuk setiap executable section
        for (const auto& section : sections) {
            // Hanya process executable sections
            if (!(section.characteristics & IMAGE_SCN_MEM_EXECUTE)) {
                continue;
            }

            // Skip sections yang legitimate berubah saat runtime
            if (section.name.find(".reloc") != std::string::npos ||
                section.name.find(".idata") != std::string::npos ||
                section.name.find(".xdata") != std::string::npos ||
                section.name.find(".pdata") != std::string::npos ||
                section.name.find(".rsrc") != std::string::npos ||
                section.name.find(".diff") != std::string::npos ||
                section.name.find("xdiff") != std::string::npos) {
                continue; // Skip verification untuk sections ini
            }

            ExecutableRegion baseline;
            baseline.rva = section.virtualAddress;
            baseline.size = section.virtualSize;
            baseline.isCodeSection = (section.name.find(".text") != std::string::npos);

            // CRITICAL: Hash dari DISK (trusted source)
            baseline.diskCRC32 = CalculateSectionHashFromDisk(fileData, section);

            // Cross-check: Hash dari memory (untuk detect early injection)
            uint8_t* memoryAddr = reinterpret_cast<uint8_t*>(m_moduleBaseAddress + section.virtualAddress);
            
            MEMORY_BASIC_INFORMATION mbi;
            if (VirtualQuery(memoryAddr, &mbi, sizeof(mbi)) > 0 && mbi.State == MEM_COMMIT) {
                // Gunakan ukuran yang sama dengan baseline.size untuk konsistensi
                // baseline.size = section.virtualSize, jadi gunakan ukuran minimum antara
                // virtualSize dan regionSize yang tersedia
                size_t sizeToHash = (section.virtualSize < static_cast<uint32_t>(mbi.RegionSize)) ? section.virtualSize : static_cast<size_t>(mbi.RegionSize);
                // Pastikan sizeToHash tidak melebihi baseline.size
                if (sizeToHash > baseline.size) {
                    sizeToHash = baseline.size;
                }
                baseline.memoryCRC32 = CalculateCRC32(memoryAddr, sizeToHash);
                
                // CRITICAL CHECK: Jika memory sudah berbeda dari disk saat baseline creation,
                // berarti sudah ada injection SEBELUM kita load!
                // Tapi HANYA untuk .text section (core code)
                // CATATAN: Relocations (ASLR) dapat menyebabkan perbedaan kecil yang legitimate
                if (baseline.diskCRC32 != baseline.memoryCRC32 && baseline.isCodeSection) {
                    // Hitung perbedaan byte-byte untuk membedakan relocations dari injection
                    // Relocations biasanya hanya mengubah beberapa bytes (< 0.1% dari section)
                    size_t rawDataSize = section.rawDataSize;
                    if (rawDataSize > 0 && rawDataSize <= fileData.size() - section.rawDataOffset) {
                        const uint8_t* diskData = fileData.data() + section.rawDataOffset;
                        size_t differentBytes = 0;
                        size_t bytesToCompare = (sizeToHash < rawDataSize) ? sizeToHash : rawDataSize;
                        
                        // Hitung jumlah byte yang berbeda
                        for (size_t i = 0; i < bytesToCompare; i++) {
                            if (diskData[i] != memoryAddr[i]) {
                                differentBytes++;
                            }
                        }
                        
                        // Relocations biasanya mengubah < 0.1% dari section (atau < 100 bytes untuk section kecil)
                        // Jika perbedaannya terlalu besar, kemungkinan ada injection
                        double diffPercentage = (bytesToCompare > 0) ? (100.0 * differentBytes / bytesToCompare) : 0.0;
                        size_t diffThreshold = (bytesToCompare > 100000) ? (bytesToCompare / 1000) : 100; // 0.1% atau max 100 bytes
                        
                        if (differentBytes > diffThreshold || diffPercentage > 0.1) {
                            // Extract executable filename from path
                            std::string exeName = "unknown";
                            if (!filePath.empty()) {
                                size_t lastSlash = filePath.find_last_of(L"\\/");
                                if (lastSlash != std::wstring::npos && lastSlash + 1 < filePath.length()) {
                                    std::wstring exeNameWide = filePath.substr(lastSlash + 1);
                                    int size_needed = WideCharToMultiByte(CP_UTF8, 0, exeNameWide.c_str(), (int)exeNameWide.length(), NULL, 0, NULL, NULL);
                                    if (size_needed > 0) {
                                        exeName.assign(size_needed, 0);
                                        WideCharToMultiByte(CP_UTF8, 0, exeNameWide.c_str(), (int)exeNameWide.length(), &exeName[0], size_needed, NULL, NULL);
                                    }
                                }
                            }
                            
                            std::stringstream ss;
                            ss << "File: " << exeName
                               << " | EARLY INJECTION DETECTED! Section " << section.name 
                               << " already modified before baseline creation. "
                               << "Disk CRC32: 0x" << std::hex << baseline.diskCRC32
                               << " Memory CRC32: 0x" << baseline.memoryCRC32
                               << " Different bytes: " << std::dec << differentBytes 
                               << " (" << std::fixed << std::setprecision(2) << diffPercentage << "%)";
                            
                            ReportViolationAndExit(L"", "EARLY_INJECTION", ss.str());
                            return;
                        }
                        // Jika perbedaannya kecil, anggap sebagai relocations yang legitimate
                        // Log untuk debugging (optional, bisa di-comment jika tidak perlu)
                        // std::cout << "Note: Small difference in .text section (likely relocations): " 
                        //           << differentBytes << " bytes (" << diffPercentage << "%)" << std::endl;
                    }
                }
            } else {
                baseline.memoryCRC32 = 0;
            }

            m_diskBaseline.push_back(baseline);
        }

        m_baselineCreated = true;
        m_baselineVerified = true;

        // Calculate baseline checksum untuk anti-tampering
        m_baselineChecksum = CalculateBaselineChecksum();
    }

    // === LAYER 4: Cross-Verification (Disk vs Memory) ===

    bool MemoryScanner::CrossVerifyDiskAndMemory(const std::vector<uint8_t>& fileData) {
        if (!m_baselineCreated) {
            return false;
        }

        m_verifiedSections.clear();

        for (const auto& baseline : m_diskBaseline) {
            uint8_t* memoryAddr = reinterpret_cast<uint8_t*>(m_moduleBaseAddress + baseline.rva);
            
            MEMORY_BASIC_INFORMATION mbi;
            if (VirtualQuery(memoryAddr, &mbi, sizeof(mbi)) == 0 || mbi.State != MEM_COMMIT) {
                continue;
            }

            // Skip non-code sections atau sections yang legitimate berubah
            auto it = m_sectionMap.find(baseline.rva);
            if (it != m_sectionMap.end()) {
                std::string sectionName = it->second.name;
                
                // Whitelist: Skip sections yang legitimate berubah saat runtime
                if (sectionName.find(".reloc") != std::string::npos ||
                    sectionName.find(".idata") != std::string::npos ||
                    sectionName.find(".xdata") != std::string::npos ||
                    sectionName.find(".pdata") != std::string::npos ||
                    sectionName.find(".rsrc") != std::string::npos ||
                    sectionName.find(".diff") != std::string::npos ||
                    sectionName.find("xdiff") != std::string::npos) {
                    continue; // Skip these sections
                }
                
                // Hanya verify .text section (core executable code)
                if (sectionName.find(".text") == std::string::npos) {
                    continue; // Skip non-text sections
                }
            }

            size_t sizeToCheck = (baseline.size < static_cast<size_t>(mbi.RegionSize)) ? baseline.size : static_cast<size_t>(mbi.RegionSize);
            uint32_t currentMemoryCRC32 = CalculateCRC32(memoryAddr, sizeToCheck);

            // CRITICAL: Bandingkan dengan memory baseline (bukan disk baseline)
            // karena relocations membuat memory berbeda dari disk sejak awal
            // baseline.memoryCRC32 adalah snapshot memory saat baseline dibuat (setelah relocations)
            // baseline.diskCRC32 digunakan untuk verifikasi bahwa file disk belum diubah
            
            bool memoryModified = false;
            if (baseline.memoryCRC32 != 0) {
                // Gunakan memory baseline jika tersedia (setelah relocations)
                memoryModified = (currentMemoryCRC32 != baseline.memoryCRC32);
            } else {
                // Fallback: jika memory baseline tidak tersedia, bandingkan dengan disk
                // tapi perlu toleransi untuk relocations (perbedaan kecil adalah normal)
                if (currentMemoryCRC32 != baseline.diskCRC32) {
                    // Hitung perbedaan untuk membedakan relocations dari injection
                    auto it_section_info = m_sectionMap.find(baseline.rva);
                    if (it_section_info != m_sectionMap.end() && !fileData.empty()) {
                        const auto& section = it_section_info->second;
                        if (section.rawDataOffset + section.rawDataSize <= fileData.size()) {
                            const uint8_t* diskData = fileData.data() + section.rawDataOffset;
                            size_t differentBytes = 0;
                            size_t bytesToCompare = (sizeToCheck < section.rawDataSize) ? sizeToCheck : section.rawDataSize;
                            
                            for (size_t i = 0; i < bytesToCompare; i++) {
                                if (diskData[i] != memoryAddr[i]) {
                                    differentBytes++;
                                }
                            }
                            
                            // Relocations biasanya < 0.1% atau < 100 bytes
                            double diffPercentage = (bytesToCompare > 0) ? (100.0 * differentBytes / bytesToCompare) : 0.0;
                            size_t diffThreshold = (bytesToCompare > 100000) ? (bytesToCompare / 1000) : 100;
                            
                            // Hanya flag jika perbedaannya signifikan
                            memoryModified = (differentBytes > diffThreshold || diffPercentage > 0.1);
                        } else {
                            memoryModified = true; // Tidak bisa verifikasi, anggap modified
                        }
                    } else {
                        memoryModified = true; // Tidak bisa verifikasi, anggap modified
                    }
                }
            }

            if (memoryModified) {
                // Code modification detected!
                std::string sectionName = (it != m_sectionMap.end()) ? it->second.name : "unknown";

                // Extract executable filename from path
                std::string exeName = "unknown";
                if (!m_executablePath.empty()) {
                    size_t lastSlash = m_executablePath.find_last_of(L"\\/");
                    if (lastSlash != std::wstring::npos && lastSlash + 1 < m_executablePath.length()) {
                        std::wstring exeNameWide = m_executablePath.substr(lastSlash + 1);
                        int size_needed = WideCharToMultiByte(CP_UTF8, 0, exeNameWide.c_str(), (int)exeNameWide.length(), NULL, 0, NULL, NULL);
                        if (size_needed > 0) {
                            exeName.assign(size_needed, 0);
                            WideCharToMultiByte(CP_UTF8, 0, exeNameWide.c_str(), (int)exeNameWide.length(), &exeName[0], size_needed, NULL, NULL);
                        }
                    }
                }

                std::stringstream ss;
                ss << "File: " << exeName
                   << " | Section: " << sectionName
                   << " | RVA: 0x" << std::hex << baseline.rva
                   << " | Expected CRC32: 0x" << (baseline.memoryCRC32 != 0 ? baseline.memoryCRC32 : baseline.diskCRC32)
                   << " | Got CRC32: 0x" << currentMemoryCRC32;

                ReportViolationAndExit(L"", "CODE_MODIFICATION", ss.str());
                return false;
            }

            // Verifikasi bahwa file disk belum diubah (optional check)
            // Ini memastikan file di disk masih sama dengan baseline
            auto it_disk_check = m_sectionMap.find(baseline.rva);
            if (it_disk_check != m_sectionMap.end() && !fileData.empty()) {
                const auto& section = it_disk_check->second;
                if (section.rawDataOffset + section.rawDataSize <= fileData.size()) {
                    uint32_t currentDiskCRC32 = CalculateSectionHashFromDisk(fileData, section);
                    if (currentDiskCRC32 != baseline.diskCRC32) {
                        // File disk telah diubah!
                        std::string sectionName = it->second.name;
                        std::string exeName = "unknown";
                        if (!m_executablePath.empty()) {
                            size_t lastSlash = m_executablePath.find_last_of(L"\\/");
                            if (lastSlash != std::wstring::npos && lastSlash + 1 < m_executablePath.length()) {
                                std::wstring exeNameWide = m_executablePath.substr(lastSlash + 1);
                                int size_needed = WideCharToMultiByte(CP_UTF8, 0, exeNameWide.c_str(), (int)exeNameWide.length(), NULL, 0, NULL, NULL);
                                if (size_needed > 0) {
                                    exeName.assign(size_needed, 0);
                                    WideCharToMultiByte(CP_UTF8, 0, exeNameWide.c_str(), (int)exeNameWide.length(), &exeName[0], size_needed, NULL, NULL);
                                }
                            }
                        }
                        
                        std::stringstream ss;
                        ss << "File: " << exeName
                           << " | Section: " << sectionName
                           << " | Disk file has been modified! Expected CRC32: 0x" << std::hex << baseline.diskCRC32
                           << " | Got CRC32: 0x" << currentDiskCRC32;
                        
                        ReportViolationAndExit(L"", "DISK_FILE_MODIFIED", ss.str());
                        return false;
                    }
                }
            }

            m_verifiedSections.insert(baseline.rva);
        }

        return true;
    }

    bool MemoryScanner::CompareCodeSections(const std::vector<uint8_t>& diskData,
                                           const uint8_t* memoryBase,
                                           const PESectionInfo& section) {
        if (section.rawDataOffset + section.rawDataSize > diskData.size()) {
            return false;
        }

        uint32_t diskHash = CalculateCRC32(
            diskData.data() + section.rawDataOffset,
            section.rawDataSize
        );

        uint32_t memoryHash = CalculateCRC32(memoryBase, section.virtualSize);

        return (diskHash == memoryHash);
    }

    // === LAYER 5: Runtime Integrity Verification ===

    bool MemoryScanner::DetectCodeCaveInjection(const uint8_t* codeSection, size_t size) {
        // Detect suspicious patterns yang indicate code caves atau shellcode
        const size_t MIN_NOP_SLED = 16;  // 16+ consecutive NOPs suspicious
        const size_t MIN_ZERO_CAVE = 32; // 32+ consecutive zeros suspicious

        size_t nopCount = 0;
        size_t zeroCount = 0;

        for (size_t i = 0; i < size; i++) {
            // Detect NOP sled (0x90)
            if (codeSection[i] == 0x90) {
                nopCount++;
                zeroCount = 0;

                if (nopCount >= MIN_NOP_SLED) {
                    // Potential NOP sled for shellcode
                    // NOTE: Beberapa compiler menggunakan NOP untuk alignment
                    // Jadi ini perlu dikombinasikan dengan checks lain
                    return true;
                }
            }
            // Detect zero-filled caves
            else if (codeSection[i] == 0x00) {
                zeroCount++;
                nopCount = 0;

                if (zeroCount >= MIN_ZERO_CAVE) {
                    // Large zero-filled region in code section
                    return true;
                }
            }
            else {
                nopCount = 0;
                zeroCount = 0;
            }
        }

        return false;
    }

    bool MemoryScanner::VerifyRegionIntegrity(uint8_t* memoryBase, size_t regionSize, uintptr_t rva) {
        if (!m_baselineCreated || !m_baselineVerified) {
            return false; // Baseline belum valid
        }

        // Cari baseline untuk RVA ini (toleransi ukuran sedikit berbeda karena alignment)
        for (const auto& baseline : m_diskBaseline) {
            // Match RVA dan ukuran harus sama atau sangat dekat (untuk toleransi alignment)
            long long sizeDiff = (long long)baseline.size - (long long)regionSize;
            if (baseline.rva == rva && (baseline.size == regionSize || (sizeDiff >= 0 ? sizeDiff : -sizeDiff) < 0x1000)) {
                size_t sizeToCheck = (baseline.size < regionSize) ? baseline.size : regionSize;
                uint32_t currentCRC32 = CalculateCRC32(memoryBase, sizeToCheck);

                // CRITICAL: Bandingkan dengan memory baseline (bukan disk baseline)
                // karena relocations membuat memory berbeda dari disk sejak awal
                bool memoryModified = false;
                
                if (baseline.memoryCRC32 != 0) {
                    // Gunakan memory baseline jika tersedia (setelah relocations)
                    // baseline.memoryCRC32 dihitung dengan ukuran baseline.size saat baseline dibuat
                    // Jadi kita harus menggunakan ukuran yang sama untuk perbandingan
                    
                    // Gunakan ukuran baseline.size untuk perbandingan (bukan sizeToCheck)
                    // karena baseline.memoryCRC32 dihitung dengan ukuran baseline.size
                    size_t sizeForComparison = baseline.size;
                    if (sizeForComparison > regionSize) {
                        sizeForComparison = regionSize; // Jangan melebihi region yang tersedia
                    }
                    
                    uint32_t currentCRC32ForComparison = CalculateCRC32(memoryBase, sizeForComparison);
                    
                    // Jika ukuran berbeda dari baseline.size, perlu recalculate baseline memory CRC32
                    uint32_t baselineMemoryCRC32 = baseline.memoryCRC32;
                    if (sizeForComparison != baseline.size) {
                        // Recalculate baseline memory CRC32 dengan ukuran yang sesuai
                        uint8_t* baselineMemoryAddr = reinterpret_cast<uint8_t*>(m_moduleBaseAddress + baseline.rva);
                        MEMORY_BASIC_INFORMATION mbi;
                        if (VirtualQuery(baselineMemoryAddr, &mbi, sizeof(mbi)) > 0 && mbi.State == MEM_COMMIT) {
                            size_t availableSize = (baseline.size < static_cast<size_t>(mbi.RegionSize)) ? baseline.size : static_cast<size_t>(mbi.RegionSize);
                            if (availableSize >= sizeForComparison) {
                                baselineMemoryCRC32 = CalculateCRC32(baselineMemoryAddr, sizeForComparison);
                            } else {
                                // Tidak bisa recalculate, gunakan baseline yang ada
                                sizeForComparison = baseline.size;
                                currentCRC32ForComparison = CalculateCRC32(memoryBase, sizeForComparison);
                            }
                        }
                    }
                    
                    memoryModified = (currentCRC32ForComparison != baselineMemoryCRC32);
                } else {
                    // Fallback: jika memory baseline tidak tersedia, bandingkan dengan disk
                    // tapi perlu toleransi untuk relocations
                    if (currentCRC32 != baseline.diskCRC32) {
                        // Untuk code sections, hitung perbedaan byte untuk membedakan relocations
                        if (baseline.isCodeSection) {
                            auto it_section = m_sectionMap.find(baseline.rva);
                            if (it_section != m_sectionMap.end()) {
                                const auto& section = it_section->second;
                                // Baca disk data untuk perbandingan
                                std::vector<uint8_t> fileData;
                                if (ReadExecutableFile(m_executablePath, fileData) && 
                                    section.rawDataOffset + section.rawDataSize <= fileData.size()) {
                                    const uint8_t* diskData = fileData.data() + section.rawDataOffset;
                                    size_t differentBytes = 0;
                                    size_t bytesToCompare = (sizeToCheck < section.rawDataSize) ? sizeToCheck : section.rawDataSize;
                                    
                                    for (size_t i = 0; i < bytesToCompare; i++) {
                                        if (diskData[i] != memoryBase[i]) {
                                            differentBytes++;
                                        }
                                    }
                                    
                                    // Relocations biasanya < 0.1% atau < 100 bytes
                                    double diffPercentage = (bytesToCompare > 0) ? (100.0 * differentBytes / bytesToCompare) : 0.0;
                                    size_t diffThreshold = (bytesToCompare > 100000) ? (bytesToCompare / 1000) : 100;
                                    
                                    // Hanya flag jika perbedaannya signifikan
                                    memoryModified = (differentBytes > diffThreshold || diffPercentage > 0.1);
                                } else {
                                    memoryModified = true; // Tidak bisa verifikasi, anggap modified
                                }
                            } else {
                                memoryModified = true; // Tidak bisa verifikasi, anggap modified
                            }
                        } else {
                            // Untuk non-code sections, gunakan heuristik SHA256
                            uint64_t sha32 = CalculateSHA256_32bit(memoryBase, sizeToCheck);
                            uint32_t sha32_lo = static_cast<uint32_t>(sha32);
                            memoryModified = (sha32_lo != baseline.memoryCRC32 && baseline.memoryCRC32 != 0);
                        }
                    }
                }

                if (memoryModified) {
                    // Jika memang ada modifikasi, baru lakukan deteksi code cave sebagai konfirmasi tambahan
                    if (baseline.isCodeSection && DetectCodeCaveInjection(memoryBase, regionSize)) {
                        // Extract executable filename dari path
                        std::string exeName = "unknown";
                        if (!m_executablePath.empty()) {
                            size_t lastSlash = m_executablePath.find_last_of(L"\\/");
                            if (lastSlash != std::wstring::npos && lastSlash + 1 < m_executablePath.length()) {
                                std::wstring exeNameWide = m_executablePath.substr(lastSlash + 1);
                                int size_needed = WideCharToMultiByte(CP_UTF8, 0, exeNameWide.c_str(), (int)exeNameWide.length(), NULL, 0, NULL, NULL);
                                if (size_needed > 0) {
                                    exeName.assign(size_needed, 0);
                                    WideCharToMultiByte(CP_UTF8, 0, exeNameWide.c_str(), (int)exeNameWide.length(), &exeName[0], size_needed, NULL, NULL);
                                }
                            }
                        }
                        
                        std::stringstream ss;
                        ss << "File: " << exeName
                           << " | Suspicious code pattern detected (NOP sled/code cave) at RVA: 0x" 
                           << std::hex << rva;
                        ReportViolationAndExit(L"", "CODE_CAVE_DETECTED", ss.str());
                        return true;
                    }

                    // Jika tidak terdeteksi code cave spesifik, tetap anggap modifikasi
                    return true;
                }

                // Tidak ada modifikasi terdeteksi
                return false;
            }
        }

        return false; // Region tidak dikenal, tidak langsung flag
    }

    bool MemoryScanner::DetectSuspiciousMemoryRegion(uint8_t* memoryBase, size_t regionSize) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(memoryBase, &mbi, sizeof(mbi)) == 0) {
            return false;
        }

        // NOTE: Deteksi RWX dinonaktifkan untuk menghindari false positive dari WoW64/sistem
        // Masih mengandalkan: CRC32 verification, code cave detection, PE validation
        
        return false;
    }

    // === Anti-Tampering untuk Baseline ===

    uint32_t MemoryScanner::CalculateBaselineChecksum() {
        if (m_diskBaseline.empty()) {
            return 0;
        }

        // Hash semua baseline data
        std::vector<uint8_t> baselineData;
        for (const auto& baseline : m_diskBaseline) {
            baselineData.insert(baselineData.end(), 
                              reinterpret_cast<const uint8_t*>(&baseline),
                              reinterpret_cast<const uint8_t*>(&baseline) + sizeof(ExecutableRegion));
        }

        return CalculateCRC32(baselineData.data(), baselineData.size());
    }

    bool MemoryScanner::VerifyBaselineIntegrity() {
        if (!m_baselineCreated) {
            return false;
        }

        uint32_t currentChecksum = CalculateBaselineChecksum();
        
        if (currentChecksum != m_baselineChecksum) {
            std::string details = "Baseline data has been tampered with! Anti-cheat compromise detected.";
            ReportViolationAndExit(L"", "BASELINE_TAMPERING", details);
            return false;
        }

        return true;
    }

    bool MemoryScanner::DetectBaselineModification() {
        // Verify baseline structure hasn't been modified in memory
        return VerifyBaselineIntegrity();
    }

    // === Main Scan Function - Multi-Layer Verification ===

    void MemoryScanner::PerformScan() {
        // === PHASE 1: Baseline Creation (ONCE, at first scan) ===
        if (!m_baselineCreated) {
            wchar_t exePath[MAX_PATH];
            if (GetModuleFileNameW(NULL, exePath, MAX_PATH) == 0) {
                std::string details = "Failed to get executable path";
                ReportViolationAndExit(L"", "PATH_RETRIEVAL_FAILED", details);
                return;
            }

            // CRITICAL: Buat baseline dari DISK, bukan memori!
            // Ini mencegah early injection bypass
            CreateBaselineFromDisk(exePath);

            if (!m_baselineCreated || !m_baselineVerified) {
                std::string details = "Baseline creation or verification failed";
                ReportViolationAndExit(L"", "BASELINE_FAILED", details);
                return;
            }
        }

        // === PHASE 2: Anti-Tampering Check (verify baseline belum dimodifikasi) ===
        if (!DetectBaselineModification()) {
            return; // Error already reported
        }

        // === PHASE 3: Runtime Integrity Verification ===
        
        // Read current executable dari disk untuk cross-verification
        std::vector<uint8_t> currentDiskData;
        if (!ReadExecutableFile(m_executablePath, currentDiskData)) {
            std::string details = "Failed to re-read executable from disk during scan";
            ReportViolationAndExit(L"", "DISK_READ_FAILED", details);
            return;
        }

        // Verify disk file hasn't been replaced
        if (!ValidatePEStructure(currentDiskData)) {
            return; // Error already reported
        }

        // Cross-verify disk vs memory
        if (!CrossVerifyDiskAndMemory(currentDiskData)) {
            return; // Error already reported
        }

        // === PHASE 4: Scan untuk Suspicious Regions ===
        
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            return;
        }

        MODULEENTRY32W me32;
        me32.dwSize = sizeof(MODULEENTRY32W);

        if (Module32FirstW(hSnapshot, &me32)) {
            do {
                if (_wcsicmp(me32.szExePath, m_executablePath.c_str()) == 0) {
                    uint8_t* baseAddr = reinterpret_cast<uint8_t*>(me32.modBaseAddr);
                    SIZE_T moduleSize = me32.modBaseSize;

                    MEMORY_BASIC_INFORMATION mbi;
                    for (size_t offset = 0; offset < moduleSize; offset += mbi.RegionSize) {
                        if (VirtualQuery(baseAddr + offset, &mbi, sizeof(mbi)) == 0) {
                            break;
                        }

                        if (mbi.State == MEM_COMMIT && 
                            (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | 
                                          PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
                            
                            uint8_t* regionBase = reinterpret_cast<uint8_t*>(mbi.BaseAddress);
                            size_t regionSize = mbi.RegionSize;

                            // Detect RWX pages (very suspicious)
                            if (DetectSuspiciousMemoryRegion(regionBase, regionSize)) {
                                // Extract executable filename from path
                                std::string exeName = "unknown";
                                if (!m_executablePath.empty()) {
                                    size_t lastSlash = m_executablePath.find_last_of(L"\\/");
                                    if (lastSlash != std::wstring::npos && lastSlash + 1 < m_executablePath.length()) {
                                        std::wstring exeNameWide = m_executablePath.substr(lastSlash + 1);
                                        int size_needed = WideCharToMultiByte(CP_UTF8, 0, exeNameWide.c_str(), (int)exeNameWide.length(), NULL, 0, NULL, NULL);
                                        if (size_needed > 0) {
                                            exeName.assign(size_needed, 0);
                                            WideCharToMultiByte(CP_UTF8, 0, exeNameWide.c_str(), (int)exeNameWide.length(), &exeName[0], size_needed, NULL, NULL);
                                        }
                                    }
                                }
                                
                                std::stringstream ss;
                                ss << "File: " << exeName
                                   << " | Suspicious RWX memory region at 0x" 
                                   << std::hex << reinterpret_cast<uintptr_t>(regionBase);
                                CloseHandle(hSnapshot);
                                ReportViolationAndExit(L"", "SUSPICIOUS_MEMORY", ss.str());
                                return;
                            }

                            // Verify executable regions integrity
                            if (mbi.Protect & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) {
                                uintptr_t rva = reinterpret_cast<uintptr_t>(regionBase) - m_moduleBaseAddress;
                                
                                if (VerifyRegionIntegrity(regionBase, regionSize, rva)) {
                                    // Extract executable filename from path
                                    std::string exeName = "unknown";
                                    if (!m_executablePath.empty()) {
                                        size_t lastSlash = m_executablePath.find_last_of(L"\\/");
                                        if (lastSlash != std::wstring::npos && lastSlash + 1 < m_executablePath.length()) {
                                            std::wstring exeNameWide = m_executablePath.substr(lastSlash + 1);
                                            int size_needed = WideCharToMultiByte(CP_UTF8, 0, exeNameWide.c_str(), (int)exeNameWide.length(), NULL, 0, NULL, NULL);
                                            if (size_needed > 0) {
                                                exeName.assign(size_needed, 0);
                                                WideCharToMultiByte(CP_UTF8, 0, exeNameWide.c_str(), (int)exeNameWide.length(), &exeName[0], size_needed, NULL, NULL);
                                            }
                                        }
                                    }
                                    
                                    std::stringstream ss;
                                    ss << "File: " << exeName
                                       << " | Code modification detected at RVA 0x" << std::hex << rva;
                                    CloseHandle(hSnapshot);
                                    ReportViolationAndExit(L"", "CODE_MODIFICATION", ss.str());
                                    return;
                                }
                            }
                        }
                    }
                    break;
                }
            } while (Module32NextW(hSnapshot, &me32));
        }

        CloseHandle(hSnapshot);
    }
}