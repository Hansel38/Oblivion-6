#include "pch.h"
#include "digital_signature_validator.h"
#include <tlhelp32.h>
#include <wintrust.h>
#include <wincrypt.h>
#include <psapi.h>
#include <softpub.h>
#include <iostream>
#include <algorithm>
#include <cwctype>
#include <map>
#include <memory>
#include <sstream>

// Forward declaration
extern void ReportViolationAndExit(const std::wstring& message, const std::string& type, const std::string& details);

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "crypt32.lib")
namespace {
    std::wstring NormalizePathForComparison(std::wstring path) {
        std::replace(path.begin(), path.end(), L'/', L'\\');
        std::transform(path.begin(), path.end(), path.begin(),
            [](wchar_t ch) { return static_cast<wchar_t>(towlower(ch)); });
        while (path.size() > 3 && (path.back() == L'\\' || path.back() == L'/')) {
            path.pop_back();
        }
        return path;
    }

    bool IsWithinDirectory(const std::wstring& path, const std::wstring& directory) {
        if (directory.empty() || path.size() <= directory.size() ||
            path.compare(0, directory.size(), directory) != 0) {
            return false;
        }
        return path[directory.size()] == L'\\' || path[directory.size()] == L'/';
    }

    bool GetEnvironmentPath(const wchar_t* variable, std::wstring& value) {
        value.clear();
        DWORD required = GetEnvironmentVariableW(variable, nullptr, 0);
        if (required <= 1 || required > 32768) return false;

        std::vector<wchar_t> buffer(required);
        const DWORD copied = GetEnvironmentVariableW(variable, buffer.data(),
                                                       static_cast<DWORD>(buffer.size()));
        if (copied == 0 || copied >= buffer.size()) return false;
        value.assign(buffer.data(), copied);
        return true;
    }

    bool GetModulePathDynamic(HANDLE process, HMODULE module, std::wstring& value) {
        value.clear();
        size_t capacity = 512;
        while (capacity <= 32768) {
            std::vector<wchar_t> buffer(capacity);
            const DWORD length = GetModuleFileNameExW(process, module, buffer.data(),
                                                       static_cast<DWORD>(buffer.size()));
            if (length == 0) return false;
            if (length < buffer.size() - 1) {
                value.assign(buffer.data(), length);
                return true;
            }
            capacity *= 2;
        }
        return false;
    }

    bool GetWindowsDirectoryDynamic(std::wstring& value) {
        value.clear();
        size_t capacity = 512;
        while (capacity <= 32768) {
            std::vector<wchar_t> buffer(capacity);
            const UINT length = GetWindowsDirectoryW(buffer.data(), static_cast<UINT>(buffer.size()));
            if (length == 0) return false;
            if (length < buffer.size()) {
                value.assign(buffer.data(), length);
                return true;
            }
            capacity = static_cast<size_t>(length) + 1;
        }
        return false;
    }
    bool IsDefinitivelyUntrustedSignatureStatus(LONG status) {
        switch (status) {
        case TRUST_E_NOSIGNATURE:
        case TRUST_E_BAD_DIGEST:
        case TRUST_E_EXPLICIT_DISTRUST:
        case TRUST_E_SUBJECT_NOT_TRUSTED:
        case TRUST_E_CERT_SIGNATURE:
        case TRUST_E_NO_SIGNER_CERT:
        case TRUST_E_COUNTER_SIGNER:
        case TRUST_E_TIME_STAMP:
        case CERT_E_UNTRUSTEDROOT:
        case CERT_E_CHAINING:
        case CERT_E_REVOKED:
        case CERT_E_EXPIRED:
        case CERT_E_WRONG_USAGE:
            return true;
        default:
            // Provider, system, I/O, and unknown statuses do not prove
            // that the executable itself is malicious or has been modified.
            return false;
        }
    }

}


// Daftar nama penerbit yang diizinkan.
// PERHATIAN: Daftar ini sangat penting. Jika terlalu ketat, akan menyebabkan false positive.
// Jika terlalu longgar, akan mengurangi keamanan.
const std::vector<std::wstring> Oblivion::DigitalSignatureValidator::m_trustedPublishers = {
    L"Microsoft Corporation",
    L"Microsoft Windows",
    L"NVIDIA Corporation",
    L"Advanced Micro Devices, Inc.",
    L"Intel Corporation",
    L"Valve Corporation", // Untuk DLL Steam
    L"Discord Inc.",      // Untuk DLL Discord
    L"Google LLC",        // Untuk DLL Chrome/Gecko
    L"Mozilla Corporation", // Untuk DLL Firefox
    L"Spotify AB",
    L"VideoLAN",
    L"Epic Games",
    L"Blizzard Entertainment",
    L"Electronic Arts",
    L"Ubisoft",
    L"Dropbox"
    // Keep this list aligned with m_expectedPublishers above.
};

// Mapping process name -> expected publisher untuk whitelist verification
// Ini digunakan untuk memverifikasi bahwa proses yang di-whitelist adalah BENAR-BENAR dari publisher yang sah
const std::map<std::wstring, std::wstring> Oblivion::DigitalSignatureValidator::m_expectedPublishers = {
    // Browser applications
    {L"chrome.exe", L"Google LLC"},
    {L"firefox.exe", L"Mozilla Corporation"},
    {L"msedge.exe", L"Microsoft Corporation"},
    {L"msedgewebview2.exe", L"Microsoft Corporation"},  // Microsoft Edge WebView2 Runtime
    
    // Communication apps
    {L"discord.exe", L"Discord Inc."},
    {L"skype.exe", L"Microsoft Corporation"},
    {L"teams.exe", L"Microsoft Corporation"},
    
    // Gaming platforms
    {L"steam.exe", L"Valve Corporation"},
    {L"steamwebhelper.exe", L"Valve Corporation"},
    
    // Development tools
    {L"vscode.exe", L"Microsoft Corporation"},
    {L"code.exe", L"Microsoft Corporation"},
    {L"devenv.exe", L"Microsoft Corporation"},
    
    // Media & Entertainment
    {L"spotify.exe", L"Spotify AB"},
    {L"vlc.exe", L"VideoLAN"},
    
    // Gaming platforms & launchers
    {L"epicgameslauncher.exe", L"Epic Games"},
    {L"easyanticheat.exe", L"Epic Games"},
    {L"battlenet.exe", L"Blizzard Entertainment"},
    {L"origin.exe", L"Electronic Arts"},
    {L"uplay.exe", L"Ubisoft"},
    {L"upc.exe", L"Ubisoft"},
    
    // Cloud storage & productivity
    {L"dropbox.exe", L"Dropbox"},
    {L"onedrive.exe", L"Microsoft Corporation"},
    {L"googledrivesync.exe", L"Google LLC"},
    
    // Unsigned utility apps are not process-whitelisted by basename; they
    // receive path/module/window checks and only skip the generic memory-byte scan.
    
    // Add more as needed
};

// Daftar DLL yang diizinkan meskipun tidak ditandatangani
// DLL ini adalah DLL legitimate dari game engine/library yang biasanya tidak ditandatangani
const std::vector<std::wstring> Oblivion::DigitalSignatureValidator::m_allowedUnsignedDlls = {
    // Game engine/library DLLs
    L"granny2.dll",       // Granny 3D animation library
    L"binkw32.dll",       // Bink video codec
    L"binkw64.dll",       // Bink video codec (64-bit)
    L"fmodex.dll",        // FMOD audio library
    L"fmodex64.dll",      // FMOD audio library (64-bit)
    L"physx.dll",         // NVIDIA PhysX
    L"physxcudart_20.dll", // NVIDIA PhysX CUDA
    L"cps.dll",           // Game engine/library DLL
    L"Mp3dec.asi",        // MP3 decoder (ASI file)
    L"Mssfast.m3d",       // Miles Sound System audio file
    
    // Intel Graphics Library
    L"ijl15.dll",         // Intel Graphics Library (Intel JPEG Library)
    L"ijl11.dll",         // Intel Graphics Library (versi lain)
    L"ijl20.dll",         // Intel Graphics Library (versi lain)
    
    // Microsoft DLLs
    L"gdiplus.dll",       // Microsoft GDI+ Graphics Library
    L"ddraw.dll",         // Microsoft DirectDraw Library
    L"dinput.dll",        // Microsoft DirectInput
    L"DCIMAN32.dll",      // Microsoft DirectX Color Management
    L"uxtheme.dll",       // Microsoft Windows UX Theme Library
    L"amsi.dll",          // Microsoft AMSI (Antimalware Scan Interface)
    L"aswAMSI.dll",       // Avast Antivirus AMSI
    L"D3DX9_42.dll",      // DirectX 9
    L"D3DX9_43.dll",      // DirectX 9
    
    // Visual C++ Runtime DLLs
    L"msvcp60.dll",       // Visual C++ Runtime
    L"msvcp90.dll",       // Visual C++ Runtime
    L"msvcp100.dll",      // Visual C++ Runtime
    L"msvcp110.dll",      // Visual C++ Runtime
    L"msvcp140.dll",      // Visual C++ Runtime
    L"msvcp140_1.dll",    // Visual C++ Runtime
    L"msvcp140_2.dll",    // Visual C++ Runtime
    L"msvcr90.dll",       // Visual C++ Runtime
    L"msvcr100.dll",      // Visual C++ Runtime
    L"msvcr110.dll",      // Visual C++ Runtime
    L"vcruntime140.dll",  // Visual C++ Runtime
    L"vccorlib140.dll",   // Visual C++ Runtime
    L"concrt140.dll",     // Visual C++ Runtime
    L"msvcm90.dll",       // Visual C++ Runtime
    
    // MFC DLLs
    L"mfc90.dll",         // Microsoft Foundation Classes
    L"mfc90u.dll",        // Microsoft Foundation Classes (Unicode)
    L"mfc100.dll",        // Microsoft Foundation Classes
    L"mfc100u.dll",       // Microsoft Foundation Classes (Unicode)
    L"mfc110.dll",        // Microsoft Foundation Classes
    L"mfc110u.dll",       // Microsoft Foundation Classes (Unicode)
    L"mfc140.dll",        // Microsoft Foundation Classes
    L"mfc140u.dll",       // Microsoft Foundation Classes (Unicode)
    L"mfcm90.dll",        // Microsoft Foundation Classes MFC
    L"mfcm90u.dll",       // Microsoft Foundation Classes MFC (Unicode)
    L"mfcm100.dll",       // Microsoft Foundation Classes MFC
    L"mfcm100u.dll",      // Microsoft Foundation Classes MFC (Unicode)
    L"mfcm140.dll",       // Microsoft Foundation Classes MFC
    L"mfcm140u.dll",      // Microsoft Foundation Classes MFC (Unicode)
    
    // Game-specific DLLs
    L"client.dll",        // Client DLL
    L"BaseSDK.dll",       // Base SDK
    L"IAPSDK.dll",        // IAP SDK
    L"libcurl.dll",       // libcurl library
    L"WebView2Loader.dll", // WebView2 Loader
    L"dbghelp.dll",       // Debug Help Library
    L"Mss32.dll",         // Miles Sound System
    L"aossdk.dll",        // AOS SDK
    L"bz32ex.dll",        // BZ32 Extension
    L"suipre.dll",        // SUI Pre
    L"v3hunt.dll",        // V3 Hunt
    
    // GameGuard/HShield DLLs
    L"NPCHK.DLL",         // GameGuard
    L"NPCIPHER.DLL",      // GameGuard
    L"NPPSK.DLL",         // GameGuard
    L"NPX.DLL",           // GameGuard
    L"npupdate.dll",      // GameGuard
    L"NPUPDATE0.DLL",     // GameGuard
    L"npkeysdk.dll",      // GameGuard
    L"npkpdb.dll",        // GameGuard
    L"npkcrypt.dll",      // GameGuard
    L"V3InetGS.dll",      // HShield
    L"V3Hunt.dll",        // HShield
    L"HSInst.dll",        // HShield
    L"AhnUpGS.dll",       // HShield
    L"AhnUpCtl.dll",      // HShield
    L"asc_main.dll",      // HShield
    L"gfs_util.dll",      // HShield
    L"gfs_proc.dll",      // HShield
    L"gfs_os.dll",        // HShield
    L"gfs_mem.dll",       // HShield
    L"gfs_file.dll",      // HShield
    L"gfs_fact.dll",      // HShield
    L"gfs_base.dll",      // HShield
    L"fse_pe.dll",        // HShield
    L"fse_fact.dll",      // HShield
    L"fse_base.dll",      // HShield
    L"asc_unp.dll",       // HShield
    L"asc_mmgr.dll",      // HShield
    L"asc_intg.dll",      // HShield
    L"asc_fse.dll",       // HShield
    L"asc_dh.dll",        // HShield
    L"asc_com.dll",       // HShield
    L"EhSvc.dll",         // HShield
    L"v3pro32s.dll",      // HShield
    L"v3bz32.dll",        // HShield
    L"ahnupctl.dll",      // HShield
    L"ahni2.dll",         // HShield
    L"Bz32Ex.dll",        // HShield
    L"AspINet.dll",       // HShield
    L"psapi.dll",         // HShield
    L"mspatcha.dll"       // HShield
};

namespace Oblivion {
    DigitalSignatureValidator::DigitalSignatureValidator() {}

    DigitalSignatureValidator::~DigitalSignatureValidator() {}

    void DigitalSignatureValidator::PerformScan() {
        std::wstring windowsDirectory;
        const bool haveWindowsDirectory = GetWindowsDirectoryDynamic(windowsDirectory);
        windowsDirectory = NormalizePathForComparison(windowsDirectory);

        std::wstring programFiles;
        std::wstring programFilesX86;
        const bool haveProgramFiles = GetEnvironmentPath(L"ProgramFiles", programFiles);
        const bool haveProgramFilesX86 = GetEnvironmentPath(L"ProgramFiles(x86)", programFilesX86);

        SYSTEM_INFO nativeSystemInfo{};
        GetNativeSystemInfo(&nativeSystemInfo);
        const bool is64BitWindows =
            nativeSystemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ||
            nativeSystemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64 ||
#ifdef PROCESSOR_ARCHITECTURE_ARM64
            nativeSystemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64 ||
#endif
            false;

        // Directory classification controls whether legacy unsigned-DLL
        // exceptions can apply. If a protected root cannot be resolved,
        // continuing would let modules fall through to the weaker allowlist.
        if (!haveWindowsDirectory || !haveProgramFiles ||
            (is64BitWindows && !haveProgramFilesX86)) {
            std::string details =
                "Unable to resolve protected module trust roots; WindowsDirectory=" +
                std::string(haveWindowsDirectory ? "available" : "unavailable") +
                ", ProgramFiles=" +
                std::string(haveProgramFiles ? "available" : "unavailable") +
                ", ProgramFiles(x86)=" +
                std::string(haveProgramFilesX86 ? "available" : "unavailable");
            ReportViolationAndExit(
                L"", "MODULE_SIGNATURE_UNAVAILABLE", details);
            return;
        }

        programFiles = NormalizePathForComparison(programFiles);
        programFilesX86 = NormalizePathForComparison(programFilesX86);

        HANDLE snapshot = INVALID_HANDLE_VALUE;
        DWORD snapshotError = ERROR_SUCCESS;
        constexpr unsigned int kSnapshotAttempts = 5;
        for (unsigned int attempt = 0; attempt < kSnapshotAttempts; ++attempt) {
            snapshot = CreateToolhelp32Snapshot(
                TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
            if (snapshot != INVALID_HANDLE_VALUE) {
                break;
            }

            snapshotError = GetLastError();
            if (snapshotError != ERROR_BAD_LENGTH) {
                break;
            }
            Sleep(10);
        }

        if (snapshot == INVALID_HANDLE_VALUE) {
            const std::string details =
                "CreateToolhelp32Snapshot failed; error=" + std::to_string(snapshotError);
            ReportViolationAndExit(L"", "MODULE_ENUMERATION_UNAVAILABLE", details);
            return;
        }

        struct SnapshotHandleDeleter {
            void operator()(HANDLE handle) const noexcept {
                if (handle != INVALID_HANDLE_VALUE && handle != NULL) {
                    CloseHandle(handle);
                }
            }
        };
        std::unique_ptr<void, SnapshotHandleDeleter> snapshotHandle(snapshot);

        MODULEENTRY32W moduleEntry{};
        moduleEntry.dwSize = sizeof(moduleEntry);
        if (!Module32FirstW(snapshot, &moduleEntry)) {
            const DWORD error = GetLastError();
            const std::string details =
                "Module32FirstW failed; error=" + std::to_string(error);
            ReportViolationAndExit(L"", "MODULE_ENUMERATION_UNAVAILABLE", details);
            return;
        }

        do {
            if (moduleEntry.hModule == GetModuleHandleW(nullptr)) {
                SetLastError(ERROR_SUCCESS);
                continue;
            }

            std::wstring modulePath;
            if (!GetModulePathDynamic(GetCurrentProcess(), moduleEntry.hModule, modulePath)) {
                const DWORD error = GetLastError();
                const std::string details =
                    "Unable to resolve a loaded module path; error=" +
                    std::to_string(error);
                ReportViolationAndExit(L"", "MODULE_PATH_UNAVAILABLE", details);
                return;
            }

            const std::wstring normalizedModulePath =
                NormalizePathForComparison(modulePath);

            // Preserve the existing policy: files under Windows/Program Files need
            // a valid Authenticode signature; other modules also require a trusted publisher.
            const bool isWindowsModule = haveWindowsDirectory &&
                IsWithinDirectory(normalizedModulePath, windowsDirectory);
            const bool isProgramFilesModule =
                (haveProgramFiles && IsWithinDirectory(normalizedModulePath, programFiles)) ||
                (haveProgramFilesX86 && IsWithinDirectory(normalizedModulePath, programFilesX86));

            const std::wstring moduleName(moduleEntry.szModule);
            ModuleTrustResult trustResult = ModuleTrustResult::Incomplete;
            std::wstring trustIssue;

            if (isWindowsModule || isProgramFilesModule) {
                LONG trustStatus = ERROR_SUCCESS;
                if (VerifyFileSignature(modulePath, &trustStatus)) {
                    trustResult = ModuleTrustResult::Trusted;
                } else {
                    trustIssue =
                        L"WinVerifyTrust failed; status=" +
                        std::to_wstring(static_cast<unsigned long>(trustStatus));
                    trustResult = IsDefinitivelyUntrustedSignatureStatus(trustStatus)
                        ? ModuleTrustResult::Untrusted
                        : ModuleTrustResult::Incomplete;
                }
            } else {
                trustResult = IsModuleTrusted(modulePath, moduleName, trustIssue);
            }

            if (trustResult == ModuleTrustResult::Incomplete) {
                std::wstringstream detailsStream;
                detailsStream << L"Module: " << moduleName
                              << L" | Path: " << modulePath
                              << L" | Reason: " << trustIssue;
                const std::wstring detailsWide = detailsStream.str();

                std::string details = "Module signature verification incomplete";
                const int required = WideCharToMultiByte(
                    CP_UTF8, 0, detailsWide.c_str(),
                    static_cast<int>(detailsWide.size()), nullptr, 0, nullptr, nullptr);
                if (required > 0) {
                    std::string converted(static_cast<size_t>(required), '\0');
                    if (WideCharToMultiByte(
                            CP_UTF8, 0, detailsWide.c_str(),
                            static_cast<int>(detailsWide.size()), &converted[0],
                            required, nullptr, nullptr) == required) {
                        details.swap(converted);
                    }
                }

                // Keep startup fail-closed, but do not classify an API/provider
                // failure as an untrusted or malicious module.
                ReportViolationAndExit(L"", "MODULE_SIGNATURE_UNAVAILABLE", details);
                return;
            }

            if (trustResult == ModuleTrustResult::Untrusted) {
                std::wstring message =
                    L"Modul tidak tepercaya (tidak ditandatangani atau penerbit tidak dikenal) terdeteksi: ";
                message += moduleEntry.szModule;
                message += L"\\n\\nPath: ";
                message += modulePath;
                message += L"\\n\\nClient akan ditutup.";

                std::wstringstream detailsStream;
                detailsStream << L"Module: " << moduleEntry.szModule
                              << L" | Path: " << modulePath
                              << L" | Reason: " << trustIssue;
                const std::wstring detailsWide = detailsStream.str();

                std::string detailsUtf8;
                const int required = WideCharToMultiByte(
                    CP_UTF8, 0, detailsWide.c_str(),
                    static_cast<int>(detailsWide.size()), nullptr, 0, nullptr, nullptr);
                if (required > 0) {
                    detailsUtf8.resize(static_cast<size_t>(required));
                    if (WideCharToMultiByte(
                            CP_UTF8, 0, detailsWide.c_str(),
                            static_cast<int>(detailsWide.size()), &detailsUtf8[0],
                            required, nullptr, nullptr) == required) {
                        ReportViolationAndExit(message, "UNTRUSTED_MODULE", detailsUtf8);
                        return;
                    }
                }

                ReportViolationAndExit(
                    message,
                    "UNTRUSTED_MODULE",
                    "Module signature or publisher is not trusted");
                return;
            }

            SetLastError(ERROR_SUCCESS);
        } while (Module32NextW(snapshot, &moduleEntry));

        const DWORD enumerationError = GetLastError();
        if (enumerationError != ERROR_NO_MORE_FILES) {
            const std::string details =
                "Module32NextW failed before enumeration completed; error=" +
                std::to_string(enumerationError);
            ReportViolationAndExit(L"", "MODULE_ENUMERATION_UNAVAILABLE", details);
            return;
        }
    }

    DigitalSignatureValidator::ModuleTrustResult
    DigitalSignatureValidator::IsModuleTrusted(
        const std::wstring& filePath,
        const std::wstring& moduleName,
        std::wstring& failureReason) {
        failureReason.clear();
        std::wstring moduleNameLower = moduleName;
        std::transform(
            moduleNameLower.begin(), moduleNameLower.end(), moduleNameLower.begin(),
            [](wchar_t ch) { return static_cast<wchar_t>(towlower(ch)); });

        // Preserve the existing compatibility allowlist for legacy unsigned DLLs.
        for (const auto& allowedDll : m_allowedUnsignedDlls) {
            std::wstring allowedLower = allowedDll;
            std::transform(
                allowedLower.begin(), allowedLower.end(), allowedLower.begin(),
                [](wchar_t ch) { return static_cast<wchar_t>(towlower(ch)); });
            if (moduleNameLower == allowedLower) {
                return ModuleTrustResult::Trusted;
            }
        }

        LONG trustStatus = ERROR_SUCCESS;
        if (!VerifyFileSignature(filePath, &trustStatus)) {
            failureReason =
                L"WinVerifyTrust failed; status=" +
                std::to_wstring(static_cast<unsigned long>(trustStatus));
            return IsDefinitivelyUntrustedSignatureStatus(trustStatus)
                ? ModuleTrustResult::Untrusted
                : ModuleTrustResult::Incomplete;
        }

        std::wstring publisherName;
        SetLastError(ERROR_SUCCESS);
        if (!GetFilePublisher(filePath, publisherName)) {
            const DWORD error = GetLastError();
            failureReason =
                L"publisher extraction failed after trust verification; error=" +
                std::to_wstring(error);
            return ModuleTrustResult::Incomplete;
        }

        std::transform(
            publisherName.begin(), publisherName.end(), publisherName.begin(),
            [](wchar_t ch) { return static_cast<wchar_t>(towlower(ch)); });

        for (const auto& trustedName : m_trustedPublishers) {
            std::wstring trustedLower = trustedName;
            std::transform(
                trustedLower.begin(), trustedLower.end(), trustedLower.begin(),
                [](wchar_t ch) { return static_cast<wchar_t>(towlower(ch)); });
            if (publisherName.find(trustedLower) != std::wstring::npos) {
                return ModuleTrustResult::Trusted;
            }
        }

        failureReason = L"Authenticode publisher is not in the trusted publisher list: " +
            publisherName;
        return ModuleTrustResult::Untrusted;
    }

    bool DigitalSignatureValidator::GetCertificateSubjectName(HMODULE hModule, std::wstring& subjectName) {
        WCHAR filePath[MAX_PATH];
        if (GetModuleFileNameExW(GetCurrentProcess(), hModule, filePath, MAX_PATH) == 0) {
            return false;
        }

        HCERTSTORE hStore = NULL;
        HCRYPTMSG hMsg = NULL;
        PCCERT_CONTEXT pCertContext = NULL;
        bool result = false;

        DWORD encoding, contentType, formatType;
        if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, filePath,
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0, &encoding, &contentType, &formatType,
            &hStore, &hMsg, NULL)) {
            return false;
        }

        // Dapatkan sertifikat penandatangan (biasanya hanya ada satu)
        PCMSG_SIGNER_INFO pSignerInfo = nullptr;
        if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_CERT_INFO_PARAM, 0, NULL, &formatType)) {
            goto cleanup;
        }

        pSignerInfo = (PCMSG_SIGNER_INFO)LocalAlloc(LPTR, formatType);
        if (!pSignerInfo) {
            goto cleanup;
        }

        if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_CERT_INFO_PARAM, 0, pSignerInfo, &formatType)) {
            LocalFree(pSignerInfo);
            goto cleanup;
        }

        // Cari sertifikat yang cocok di toko
        pCertContext = CertFindCertificateInStore(hStore, encoding, 0, CERT_FIND_SUBJECT_CERT, pSignerInfo, NULL);
        LocalFree(pSignerInfo);

        if (pCertContext) {
            DWORD nameSize = 0;
            // Dapatkan ukuran nama
            nameSize = CertGetNameStringW(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, NULL, 0);
            if (nameSize > 0) {
                std::vector<WCHAR> nameBuffer(nameSize);
                // Dapatkan nama sebenarnya
                if (CertGetNameStringW(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, nameBuffer.data(), nameSize) > 0) {
                    subjectName = nameBuffer.data();
                    result = true;
                }
            }
            CertFreeCertificateContext(pCertContext);
        }

    cleanup:
        if (hStore) CertCloseStore(hStore, 0);
        if (hMsg) CryptMsgClose(hMsg);
        return result;
    }

    // Static function untuk verifikasi file signature (untuk process verification)
    bool DigitalSignatureValidator::VerifyFileSignature(
        const std::wstring& filePath,
        LONG* trustStatus) {
        WINTRUST_FILE_INFO fileInfo = { 0 };
        fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
        fileInfo.pcwszFilePath = filePath.c_str();
        fileInfo.hFile = NULL;
        fileInfo.pgKnownSubject = NULL;

        WINTRUST_DATA winTrustData = { 0 };
        winTrustData.cbStruct = sizeof(WINTRUST_DATA);
        winTrustData.pPolicyCallbackData = NULL;
        winTrustData.pSIPClientData = NULL;
        winTrustData.dwUIChoice = WTD_UI_NONE;
        winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
        winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
        winTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
        winTrustData.hWVTStateData = NULL;
        winTrustData.pwszURLReference = NULL;
        winTrustData.dwProvFlags = WTD_SAFER_FLAG;
        winTrustData.dwUIContext = 0;
        winTrustData.pFile = &fileInfo;

        GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

        // WinVerifyTrust returns a LONG status code; only zero means trusted.
        const LONG result = WinVerifyTrust(NULL, &policyGUID, &winTrustData);
        if (trustStatus != nullptr) {
            *trustStatus = result;
        }

        winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(NULL, &policyGUID, &winTrustData);

        return result == ERROR_SUCCESS;
    }

    // Used only after the caller has verified that the executable path is
    // inside the Windows directory. This helper checks the file-signature path;
    // it does not perform a separate catalog lookup. A missing embedded signature
    // is therefore incomplete, not proof that a Windows binary is untrusted.
    DigitalSignatureValidator::ProcessSignatureResult
    DigitalSignatureValidator::VerifyWindowsSystemProcessSignatureDetailed(
        const std::wstring& processPath,
        std::wstring& failureReason) {
        failureReason.clear();
        if (processPath.empty()) {
            failureReason = L"Windows process image path is empty";
            return ProcessSignatureResult::Incomplete;
        }

        LONG trustStatus = ERROR_SUCCESS;
        if (VerifyFileSignature(processPath, &trustStatus)) {
            return ProcessSignatureResult::Trusted;
        }

        failureReason = L"WinVerifyTrust failed; status=" +
            std::to_wstring(static_cast<unsigned long>(trustStatus));
        if (trustStatus == TRUST_E_NOSIGNATURE) {
            failureReason = L"No embedded signature was found; catalog trust was not established";
            return ProcessSignatureResult::Incomplete;
        }

        return IsDefinitivelyUntrustedSignatureStatus(trustStatus)
            ? ProcessSignatureResult::Untrusted
            : ProcessSignatureResult::Incomplete;
    }

    // Static function untuk mendapatkan publisher dari file
    bool DigitalSignatureValidator::GetFilePublisher(const std::wstring& filePath, std::wstring& publisherName) {
        HCERTSTORE hStore = NULL;
        HCRYPTMSG hMsg = NULL;
        PCCERT_CONTEXT pCertContext = NULL;
        PCMSG_SIGNER_INFO pSignerInfo = NULL;
        bool result = false;

        DWORD encoding, contentType, formatType;
        if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, filePath.c_str(),
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0, &encoding, &contentType, &formatType,
            &hStore, &hMsg, NULL)) {
            return false;
        }

        DWORD dwSize = 0;
        if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_CERT_INFO_PARAM, 0, NULL, &dwSize)) {
            goto cleanup;
        }

        pSignerInfo = (PCMSG_SIGNER_INFO)LocalAlloc(LPTR, dwSize);
        if (!pSignerInfo) {
            goto cleanup;
        }

        if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_CERT_INFO_PARAM, 0, pSignerInfo, &dwSize)) {
            LocalFree(pSignerInfo);
            pSignerInfo = NULL;
            goto cleanup;
        }

        pCertContext = CertFindCertificateInStore(hStore, encoding, 0, CERT_FIND_SUBJECT_CERT, pSignerInfo, NULL);
        LocalFree(pSignerInfo);
        pSignerInfo = NULL;

        if (pCertContext) {
            DWORD nameSize = CertGetNameStringW(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, NULL, 0);
            if (nameSize > 0) {
                std::vector<WCHAR> nameBuffer(nameSize);
                if (CertGetNameStringW(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, nameBuffer.data(), nameSize) > 0) {
                    publisherName = nameBuffer.data();
                    result = true;
                }
            }
            CertFreeCertificateContext(pCertContext);
        }

    cleanup:
        if (hStore) CertCloseStore(hStore, 0);
        if (hMsg) CryptMsgClose(hMsg);
        return result;
    }

    // Separate definitive trust failures from provider or publisher-extraction failures.
    DigitalSignatureValidator::ProcessSignatureResult
    DigitalSignatureValidator::VerifyProcessSignatureDetailed(
        const std::wstring& processPath,
        const std::wstring& expectedPublisher,
        std::wstring& failureReason) {
        failureReason.clear();

        if (processPath.empty()) {
            failureReason = L"process image path is empty";
            return ProcessSignatureResult::Incomplete;
        }
        if (expectedPublisher.empty()) {
            failureReason = L"expected publisher configuration is empty";
            return ProcessSignatureResult::Incomplete;
        }

        LONG trustStatus = ERROR_SUCCESS;
        if (!VerifyFileSignature(processPath, &trustStatus)) {
            failureReason =
                L"WinVerifyTrust failed; status=" +
                std::to_wstring(static_cast<unsigned long>(trustStatus));
            return IsDefinitivelyUntrustedSignatureStatus(trustStatus)
                ? ProcessSignatureResult::Untrusted
                : ProcessSignatureResult::Incomplete;
        }

        std::wstring actualPublisher;
        SetLastError(ERROR_SUCCESS);
        if (!GetFilePublisher(processPath, actualPublisher)) {
            const DWORD error = GetLastError();
            failureReason =
                L"publisher extraction failed after trust verification; error=" +
                std::to_wstring(error);
            return ProcessSignatureResult::Incomplete;
        }

        std::wstring lowerActual = actualPublisher;
        std::wstring lowerExpected = expectedPublisher;
        std::transform(
            lowerActual.begin(), lowerActual.end(), lowerActual.begin(),
            [](wchar_t ch) { return static_cast<wchar_t>(towlower(ch)); });
        std::transform(
            lowerExpected.begin(), lowerExpected.end(), lowerExpected.begin(),
            [](wchar_t ch) { return static_cast<wchar_t>(towlower(ch)); });

        // Keep the existing comparison semantics unchanged in this bug fix.
        if (lowerActual.find(lowerExpected) != std::wstring::npos) {
            return ProcessSignatureResult::Trusted;
        }

        failureReason = L"Authenticode publisher did not match the expected publisher";
        return ProcessSignatureResult::Untrusted;
    }

    bool DigitalSignatureValidator::VerifyProcessSignature(
        const std::wstring& processPath,
        const std::wstring& expectedPublisher) {
        std::wstring failureReason;
        return VerifyProcessSignatureDetailed(
            processPath, expectedPublisher, failureReason) ==
            ProcessSignatureResult::Trusted;
    }

}