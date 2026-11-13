#include "pch.h"
#include "advanced_process_heuristics.h"
#include "digital_signature_validator.h"
#include <limits>
#include <cstddef>
#include <tlhelp32.h>
#include <vector>
#include <memory>
#include <algorithm>
#include <cwctype>
#include <sstream>
#include <iostream>
#include <map>
#include <psapi.h>
#include <winternl.h>

// NtQuerySystemInformation for handle enumeration
typedef NTSTATUS (NTAPI* NtQuerySystemInformationFn)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength);

// System handle information structures
typedef struct _SYSTEM_HANDLE {
    ULONG ProcessId;
    BYTE ObjectTypeNumber;
    BYTE Flags;
    USHORT Handle;
    PVOID Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG HandleCount;
    SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

#define SYSTEM_HANDLE_INFORMATION_CLASS 16
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004

// Forward declaration
extern void ReportViolationAndExit(const std::wstring& message, const std::string& type, const std::string& details);

namespace {
    enum class ProcessWhitelistResult {
        NotWhitelisted,
        Whitelisted,
        Incomplete
    };

    // Cache untuk signature verification - menghindari re-verify proses yang sama
    // Key: Process Path (lowercase), Value: Is Verified (true/false)
    std::map<std::wstring, bool> g_signatureCache;
    
    DWORD GetProtectedProcessId() {
        return GetCurrentProcessId();
    }

    std::wstring ToLowerCopy(const std::wstring& input) {
        std::wstring lowered = input;
        std::transform(lowered.begin(), lowered.end(), lowered.begin(), [](wchar_t ch) {
            return static_cast<wchar_t>(towlower(ch));
            });
        return lowered;
    }

    struct WindowSearchContext {
        DWORD targetProcessId = 0;
        std::wstring matchedClass;
        std::wstring matchedTitle;
        std::wstring scanIssue;
        bool matched = false;
        bool incomplete = false;
        bool searchingTitle = false; // true = searching for title patterns, false = searching for class
        int suspiciousControlCount = 0; // Count of suspicious child controls (for UI element detection)
    };

    void MarkWindowInspectionIncomplete(
        WindowSearchContext& context,
        const wchar_t* operation,
        DWORD error) {
        context.incomplete = true;
        if (context.scanIssue.empty()) {
            context.scanIssue = operation;
            if (error != ERROR_SUCCESS) {
                context.scanIssue += L"; error=" + std::to_wstring(error);
            }
        }
    }

    // Cheat Engine DLL signatures - komprehensif untuk berbagai versi CE
    const std::vector<std::wstring> kSuspiciousModules = {
        // Core CE DLLs
        L"dbk32.dll",
        L"dbk64.dll",
        L"dbvm.dll",
        L"dbvm32.dll",
        L"dbvm64.dll",
        
        // CE Client & Components
        L"ceclient.dll",
        L"ceserver.dll",
        L"celua.dll",
        L"lua53-64.dll",
        L"lua53-32.dll",
        
        // Speedhack modules
        L"speedhack-i386.dll",
        L"speedhack-x86_64.dll",
        L"speedhack.dll",
        
        // Kernel modules & drivers
        L"kernelmoduleunloader.dll",
        L"vehdebug-x86_64.dll",
        L"vehdebug-i386.dll",
        
        // Plugin & Extension DLLs
        L"d3dhook.dll",
        L"d3dhook64.dll",
        L"xinput1_3ce.dll",
        L"xinput9_1_0ce.dll",
        
        // CE Utilities
        L"autoassembler.dll",
        L"symbolhandler.dll",
        L"disassembler.dll"
    };

    // Window class signatures untuk berbagai versi CE dan tools
    const std::vector<std::wstring> kSuspiciousWindowClasses = {
        // Cheat Engine-specific main forms.
        // Generic TForm1/TMainForm names are intentionally excluded: they are
        // common application form names and are not reliable cheat indicators.
        L"tceform",
        L"tcemainform",
        L"tcheatengine",

        // CE dialogs & windows
        L"tmemoryview",
        L"tmemorybrowser",
        L"tmemoryviewer",
        L"tdissectwindow",
        L"tformaddresslist",
        L"tfoundlistform",
        L"tfoundcodeform",
        L"tscanform",
        L"tadvancedoptionsform",
        
        // CE utilities & tools
        L"tautoassembler",
        L"tautoassemblerform",
        L"tlazarusform",
        L"tstructurefrm",
        L"tpointerscanner",
        L"tpointerfinder",
        L"theaplist",
        L"tdbvmform",
        
        // CE Lua windows
        L"tluaengine",
        L"tluaform",
        
        // x64dbg. Generic Qt window classes are excluded because Qt creates
        // them from window flags for many unrelated applications.
        L"x64dbgmain",
        
        // OllyDbg variants
        L"ollydbg",
        L"odbg",
        
        // IDA Pro
        L"idawindow",
        
        // Other debuggers
        L"windbgframeclass",
        L"procmon_window_class"
    };

    // Whitelist: Process sistem Windows yang tidak boleh di-scan untuk menghindari false positive
    const std::vector<std::wstring> kSystemProcessWhitelist = {
        // Windows Core Processes
        L"explorer.exe",
        L"svchost.exe",
        L"services.exe",
        L"lsass.exe",
        L"csrss.exe",
        L"smss.exe",
        L"wininit.exe",
        L"winlogon.exe",
        L"dwm.exe",
        L"taskhostw.exe",
        L"taskhost.exe",
        L"sihost.exe",
        L"ctfmon.exe",
        L"conhost.exe",
        L"fontdrvhost.exe",
        L"runtimebroker.exe",
        L"dllhost.exe",
        L"system",
        L"system idle process",
        L"registry",
        
        // Windows Search & Indexing
        L"searchhost.exe",
        L"searchindexer.exe",
        L"searchprotocolhost.exe",
        L"searchfilterhost.exe",
        
        // Windows Defender & Security
        L"msmpeng.exe",
        L"mssense.exe",
        L"securityhealthservice.exe",
        L"securityhealthsystray.exe",
        L"smartscreen.exe",
        L"sgrmbroker.exe",
        
        // Windows Update & Maintenance
        L"wuauclt.exe",
        L"trustedinstaller.exe",
        L"tiworker.exe",
        L"usocoreworker.exe",
        
        // Windows Shell & UI
        L"shellexperiencehost.exe",
        L"startmenuexperiencehost.exe",
        L"textinputhost.exe",
        L"applicationframehost.exe",
        L"systemsettings.exe",
        
        // Windows Audio Services
        L"audiodg.exe",  // Audio Device Graph Isolation (Windows audio service)
        
        // Open-source utilities (no signature verification - often unsigned)
        L"notepad++.exe",
        L"7zfm.exe",
        L"7zg.exe",
        L"vlc.exe",
        L"winrar.exe",
        
        // Development tools (no signature verification - often unsigned during development)
        L"vcpkgsrv.exe",  // Visual Studio Package Server
        
        // Common legitimate software (REQUIRES SIGNATURE VERIFICATION)
        // These processes MUST be verified with digital signature to prevent spoofing
        L"chrome.exe",
        L"firefox.exe",
        L"msedge.exe",
        L"msedgewebview2.exe",  // Microsoft Edge WebView2 Runtime
        L"discord.exe",
        L"steam.exe",
        L"steamwebhelper.exe",
        L"vscode.exe",
        L"code.exe",
        L"devenv.exe",
        L"skype.exe",
        L"teams.exe",
        // Media & Entertainment
        L"spotify.exe",
        // Gaming platforms
        L"epicgameslauncher.exe",
        L"easyanticheat.exe",
        L"battlenet.exe",
        L"origin.exe",
        L"uplay.exe",
        L"upc.exe",
        // Cloud & Productivity
        L"dropbox.exe",
        L"onedrive.exe",
        L"googledrivesync.exe"
    };

    // Proses yang HARUS diverifikasi dengan digital signature (tidak boleh di-spoof)
    // Ini adalah subset dari whitelist yang rentan terhadap spoofing
    const std::vector<std::wstring> kSignatureVerificationRequired = {
        L"chrome.exe",
        L"firefox.exe",
        L"msedge.exe",
        L"msedgewebview2.exe",  // Microsoft Edge WebView2 Runtime
        L"discord.exe",
        L"steam.exe",
        L"steamwebhelper.exe",
        L"vscode.exe",
        L"code.exe",
        L"devenv.exe",
        L"skype.exe",
        L"teams.exe",
        L"spotify.exe",
        L"epicgameslauncher.exe",
        L"easyanticheat.exe",
        L"battlenet.exe",
        L"origin.exe",
        L"uplay.exe",
        L"upc.exe",
        L"dropbox.exe",
        L"onedrive.exe",
        L"googledrivesync.exe"
        // NOTE: notepad++, 7zip, vlc, winrar tidak require signature verification
        // karena sering unsigned (open-source/freeware)
    };

    // Resolve the complete process image path without assuming MAX_PATH is sufficient.
    bool GetProcessImagePath(
        DWORD processId,
        std::wstring& processPath,
        DWORD* failureError = nullptr) {
        processPath.clear();
        if (failureError != nullptr) {
            *failureError = ERROR_SUCCESS;
        }

        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
        if (hProcess == NULL) {
            if (failureError != nullptr) {
                *failureError = GetLastError();
            }
            return false;
        }

        constexpr size_t kInitialPathCapacity = 512;
        constexpr size_t kMaximumPathCapacity = 32768;
        std::vector<wchar_t> buffer(kInitialPathCapacity);
        bool resolved = false;
        DWORD lastError = ERROR_SUCCESS;

        while (buffer.size() <= kMaximumPathCapacity) {
            DWORD length = static_cast<DWORD>(buffer.size());
            if (QueryFullProcessImageNameW(hProcess, 0, buffer.data(), &length)) {
                processPath.assign(buffer.data(), length);
                resolved = true;
                break;
            }

            lastError = GetLastError();
            if (lastError != ERROR_INSUFFICIENT_BUFFER ||
                buffer.size() == kMaximumPathCapacity) {
                break;
            }

            buffer.resize((std::min)(buffer.size() * 2, kMaximumPathCapacity));
        }

        CloseHandle(hProcess);
        if (!resolved && failureError != nullptr) {
            *failureError = lastError;
        }
        return resolved;
    }

    std::wstring GetProcessPath(DWORD processId) {
        std::wstring processPath;
        return GetProcessImagePath(processId, processPath) ? processPath : L"";
    }

    ProcessWhitelistResult IsProcessWhitelisted(
        const std::wstring& processName,
        DWORD processId = 0,
        std::wstring* scanIssue = nullptr) {
        if (scanIssue != nullptr) {
            scanIssue->clear();
        }
        std::wstring lowerName = ToLowerCopy(processName);
        
        // Cek apakah process ada di whitelist
        bool isInWhitelist = false;
        for (const auto& whitelisted : kSystemProcessWhitelist) {
            if (lowerName == whitelisted) {
                isInWhitelist = true;
                break;
            }
        }
        
        if (!isInWhitelist) {
            return ProcessWhitelistResult::NotWhitelisted;
        }
        
        // Cek apakah proses ini memerlukan verifikasi signature
        bool needsSignatureVerification = false;
        for (const auto& requiresVerification : kSignatureVerificationRequired) {
            if (lowerName == requiresVerification) {
                needsSignatureVerification = true;
                break;
            }
        }
        
        // Jika tidak perlu verifikasi signature (proses Windows system), langsung return true
        if (!needsSignatureVerification) {
            return ProcessWhitelistResult::Whitelisted;
        }
        
        // Proses memerlukan verifikasi signature - cegah spoofing!
        if (processId == 0) {
            if (scanIssue != nullptr) {
                *scanIssue = L"signature whitelist check requires a process ID";
            }
            return ProcessWhitelistResult::Incomplete;
        }
        
        // Dapatkan full path dari process
        std::wstring processPath;
        DWORD pathError = ERROR_SUCCESS;
        if (!GetProcessImagePath(processId, processPath, &pathError)) {
            if (scanIssue != nullptr) {
                *scanIssue = L"signature whitelist image-path query failed; error=" +
                    std::to_wstring(pathError);
            }
            std::wcout << L"[AdvHeuristics] WARNING: Cannot verify whitelist path for process: "
                       << processName << L" (PID: " << processId
                       << L", error: " << pathError << L")" << std::endl;
            return ProcessWhitelistResult::Incomplete;
        }
        
        // Normalize path untuk cache (lowercase)
        std::wstring cacheKey = processPath;
        std::transform(cacheKey.begin(), cacheKey.end(), cacheKey.begin(), ::towlower);
        
        // Cek cache terlebih dahulu untuk menghindari re-verification
        auto cacheIt = g_signatureCache.find(cacheKey);
        if (cacheIt != g_signatureCache.end()) {
            // Cache hit! Return hasil yang sudah pernah diverifikasi (SILENT - no log spam)
            bool cachedResult = cacheIt->second;
            
            // Hanya log jika SPOOFING terdeteksi (penting!)
            if (!cachedResult) {
                std::wcout << L"[AdvHeuristics] SPOOFING DETECTED (cached): " << processName 
                           << L" (PID: " << processId << L")" << std::endl;
            }
            // Jika valid, tidak perlu log (sudah di-log saat pertama kali verify)
            
            return cachedResult ? ProcessWhitelistResult::Whitelisted : ProcessWhitelistResult::NotWhitelisted;
        }
        
        // Dapatkan expected publisher dari DigitalSignatureValidator
        const auto& publisherMap = Oblivion::DigitalSignatureValidator::m_expectedPublishers;
        auto it = publisherMap.find(lowerName);
        
        if (it == publisherMap.end()) {
            // Tidak ada expected publisher - ini seharusnya tidak terjadi karena kita sudah filter di atas
            std::wcout << L"[AdvHeuristics] WARNING: No expected publisher for: "
                       << processName << std::endl;
            if (scanIssue != nullptr) {
                *scanIssue = L"expected publisher is missing from the whitelist configuration";
            }
            return ProcessWhitelistResult::Incomplete;
        }
        
        const std::wstring& expectedPublisher = it->second;
        
        // Verifikasi digital signature dengan expected publisher
        std::wcout << L"[AdvHeuristics] Verifying signature: " << processName << L" (PID: " << processId << L")..." << std::endl;
        bool isVerified = Oblivion::DigitalSignatureValidator::VerifyProcessSignature(processPath, expectedPublisher);
        
        // Simpan hasil ke cache
        g_signatureCache[cacheKey] = isVerified;
        
        if (!isVerified) {
            // SPOOFING DETECTED!
            std::wcout << L"[AdvHeuristics] SPOOFING DETECTED: Process \"" << processName 
                       << L"\" (PID: " << processId << L") failed signature verification!" << std::endl;
            std::wcout << L"[AdvHeuristics] Path: " << processPath << std::endl;
            std::wcout << L"[AdvHeuristics] Expected publisher: " << expectedPublisher << std::endl;
            
            // Log detail untuk debugging
            std::wstring actualPublisher;
            std::wstring actualPublisherInfo = L"No signature";
            if (Oblivion::DigitalSignatureValidator::GetFilePublisher(processPath, actualPublisher)) {
                std::wcout << L"[AdvHeuristics] Actual publisher: " << actualPublisher << std::endl;
                actualPublisherInfo = actualPublisher;
            } else {
                std::wcout << L"[AdvHeuristics] No valid signature found!" << std::endl;
            }
            
            // Build details untuk report ke server
            std::wstringstream detailsStream;
            detailsStream << L"Process: " << processName 
                         << L" (PID: " << processId << L")"
                         << L" | Path: " << processPath
                         << L" | Expected: " << expectedPublisher
                         << L" | Actual: " << actualPublisherInfo;
            
            std::wstring detailsWide = detailsStream.str();
            
            // Convert ke UTF-8 untuk server
            int size_needed = WideCharToMultiByte(CP_UTF8, 0, detailsWide.c_str(), (int)detailsWide.length(), NULL, 0, NULL, NULL);
            std::string details_utf8;
            if (size_needed > 0) {
                details_utf8.resize(size_needed);
                WideCharToMultiByte(CP_UTF8, 0, detailsWide.c_str(), (int)detailsWide.length(), &details_utf8[0], size_needed, NULL, NULL);
            }
            
            // REPORT KE SERVER DAN EXIT
            std::wcout << L"[AdvHeuristics] Reporting spoofing to server..." << std::endl;
            ReportViolationAndExit(L"", "SIGNATURE_SPOOFING", details_utf8);
            
            return ProcessWhitelistResult::NotWhitelisted; // Normally unreachable after ExitProcess
        }
        
        // Signature verified successfully
        std::wcout << L"[AdvHeuristics] Signature verified: " << processName 
               << L" (PID: " << processId << L") - Publisher: " << expectedPublisher << std::endl;
        return ProcessWhitelistResult::Whitelisted;
    }

    // Enable SeDebugPrivilege and verify that Windows assigned the privilege.
    bool EnableDebugPrivilege() {
        HANDLE hToken = NULL;
        TOKEN_PRIVILEGES tokenPrivileges{};
        LUID luid{};

        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
            return false;
        }

        if (!LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &luid)) {
            const DWORD error = GetLastError();
            CloseHandle(hToken);
            SetLastError(error);
            return false;
        }

        tokenPrivileges.PrivilegeCount = 1;
        tokenPrivileges.Privileges[0].Luid = luid;
        tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        SetLastError(ERROR_SUCCESS);
        const BOOL adjusted =
            AdjustTokenPrivileges(hToken, FALSE, &tokenPrivileges, 0, NULL, NULL);
        const DWORD error = GetLastError();
        CloseHandle(hToken);
        SetLastError(error);

        return adjusted != FALSE && error == ERROR_SUCCESS;
    }

    // Get process name from PID using the dynamically sized image-path helper.
    std::wstring GetProcessName(DWORD processId) {
        std::wstring fullPath;
        if (!GetProcessImagePath(processId, fullPath)) {
            return L"";
        }

        const size_t lastSlash = fullPath.find_last_of(L"\\/");
        if (lastSlash != std::wstring::npos) {
            return fullPath.substr(lastSlash + 1);
        }
        return fullPath;
    }
    
    // Memory signatures - pola byte khas CE di memory (IMPROVED - lebih spesifik)
    struct MemorySignature {
        const wchar_t* name;
        const BYTE* pattern;
        size_t patternSize;
        const BYTE* mask;
        bool requiresExecutableMemory; // True jika harus di executable region
    };
    
    // CE specific code signature - DBK driver initialization pattern
    const BYTE dbkInitPattern[] = { 
        0x44, 0x42, 0x4B, 0x33, 0x32, // "DBK32" signature
        0x2E, 0x73, 0x79, 0x73         // ".sys"
    };
    const BYTE dbkInitMask[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
    
    // CE Lua engine specific pattern
    const BYTE luaEnginePattern[] = {
        0x43, 0x45, 0x4C, 0x75, 0x61,  // "CELua"
        0x00, 0x00, 0x00, 0x00
    };
    const BYTE luaEngineMask[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00 };
    
    // Speedhack signature - characteristic timer manipulation code
    const BYTE speedhackPattern[] = {
        0x48, 0x89, 0x5C, 0x24, 0x08,  // mov [rsp+8], rbx
        0x57,                           // push rdi
        0x48, 0x83, 0xEC, 0x20         // sub rsp, 20h
    };
    const BYTE speedhackMask[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
    
    const std::vector<MemorySignature> kMemorySignatures = {
        { L"DBK_DRIVER", dbkInitPattern, sizeof(dbkInitPattern), dbkInitMask, false },
        { L"CE_LUA_ENGINE", luaEnginePattern, sizeof(luaEnginePattern), luaEngineMask, false },
        { L"SPEEDHACK_CODE", speedhackPattern, sizeof(speedhackPattern), speedhackMask, true }
    };

    BOOL CALLBACK EnumWindowsForProcess(HWND hwnd, LPARAM lParam) {
        auto* ctx = reinterpret_cast<WindowSearchContext*>(lParam);
        if (!ctx) {
            return FALSE;
        }

        DWORD windowProcessId = 0;
        if (GetWindowThreadProcessId(hwnd, &windowProcessId) == 0) {
            MarkWindowInspectionIncomplete(
                *ctx, L"GetWindowThreadProcessId failed", ERROR_SUCCESS);
            return TRUE;
        }
        if (windowProcessId != ctx->targetProcessId) {
            return TRUE;
        }

        if (ctx->searchingTitle) {
            // Search for suspicious window titles
            wchar_t windowTitle[512] = { 0 };
            SetLastError(ERROR_SUCCESS);
            const int titleLen = GetWindowTextW(
                hwnd, windowTitle,
                static_cast<int>(sizeof(windowTitle) / sizeof(windowTitle[0])));
            if (titleLen == 0) {
                const DWORD error = GetLastError();
                if (error != ERROR_SUCCESS) {
                    MarkWindowInspectionIncomplete(
                        *ctx, L"GetWindowTextW failed", error);
                }
            }

#ifdef _DEBUG
            if (titleLen > 0) {
                std::wstring debugMsg = L"[AdvHeuristics] Found window title: " + std::wstring(windowTitle, titleLen) + L"\n";
                OutputDebugStringW(debugMsg.c_str());
            }
#endif
            
            if (titleLen > 0) {
                std::wstring title(windowTitle, titleLen);
                std::wstring lowerTitle = ToLowerCopy(title);
                
                // Pattern 1: CE window title format "[PID]-[ProcessName]" or "[PID]-[GameName]"
                // Example: "00001C0C-Republic-RO" atau "00001234-game.exe"
                if (title.length() > 5 && title[0] >= L'0' && title[0] <= L'9') {
                    size_t dashPos = title.find(L'-');
                    if (dashPos != std::wstring::npos && dashPos <= 8) {
                        // Check if before dash is hex PID
                        bool isHexPID = true;
                        for (size_t i = 0; i < dashPos; ++i) {
                            wchar_t ch = title[i];
                            if (!((ch >= L'0' && ch <= L'9') || (ch >= L'A' && ch <= L'F') || (ch >= L'a' && ch <= L'f'))) {
                                isHexPID = false;
                                break;
                            }
                        }
                        if (isHexPID) {
                            ctx->matchedTitle = L"CE_PID_PATTERN: " + title;
                            ctx->matched = true;
#ifdef _DEBUG
                            OutputDebugStringW(L"[AdvHeuristics] DETECTED CE PID PATTERN!\n");
#endif
                            return FALSE;
                        }
                    }
                }
                
                // Pattern 2: Contains "cheat engine" dalam title
                if (lowerTitle.find(L"cheat engine") != std::wstring::npos ||
                    lowerTitle.find(L"cheatengine") != std::wstring::npos) {
                    ctx->matchedTitle = L"CE_TITLE: " + title;
                    ctx->matched = true;
#ifdef _DEBUG
                    OutputDebugStringW(L"[AdvHeuristics] DETECTED CE TITLE!\n");
#endif
                    return FALSE;
                }
                
                // Pattern 3: CE version pattern "Cheat Engine 7.x" atau "CE 7.x"
                if (lowerTitle.find(L"ce ") != std::wstring::npos && 
                    (lowerTitle.find(L"7.") != std::wstring::npos || lowerTitle.find(L"6.") != std::wstring::npos)) {
                    ctx->matchedTitle = L"CE_VERSION: " + title;
                    ctx->matched = true;
#ifdef _DEBUG
                    OutputDebugStringW(L"[AdvHeuristics] DETECTED CE VERSION!\n");
#endif
                    return FALSE;
                }
                
                // Pattern 4: "No Process Selected" - CE default title saat belum attach
                if (lowerTitle.find(L"no process selected") != std::wstring::npos) {
                    ctx->matchedTitle = L"CE_NO_PROCESS: " + title;
                    ctx->matched = true;
#ifdef _DEBUG
                    OutputDebugStringW(L"[AdvHeuristics] DETECTED CE NO PROCESS TITLE!\n");
#endif
                    return FALSE;
                }
                
                // Pattern 5: Modified CE versions (bossb, etc)
                if (lowerTitle.find(L"bossb") != std::wstring::npos ||
                    lowerTitle.find(L"boss b") != std::wstring::npos) {
                    ctx->matchedTitle = L"CE_MODIFIED: " + title;
                    ctx->matched = true;
#ifdef _DEBUG
                    OutputDebugStringW(L"[AdvHeuristics] DETECTED MODIFIED CE (bossb)!\n");
#endif
                    return FALSE;
                }
            }
        } else {
            // Search for suspicious window classes
            wchar_t className[256] = { 0 };
            SetLastError(ERROR_SUCCESS);
            const int len = GetClassNameW(
                hwnd, className,
                static_cast<int>(sizeof(className) / sizeof(className[0])));
            if (len == 0) {
                const DWORD error = GetLastError();
                if (error != ERROR_SUCCESS) {
                    MarkWindowInspectionIncomplete(
                        *ctx, L"GetClassNameW failed", error);
                }
                return TRUE;
            }

            std::wstring lowered = ToLowerCopy(className);
            for (const auto& suspiciousClass : kSuspiciousWindowClasses) {
                if (lowered == suspiciousClass) {
                    ctx->matchedClass.assign(className, len);
                    ctx->matched = true;
                    return FALSE;
                }
            }
        }

        return TRUE;
    }
    
    // Callback untuk enumerate child controls di dalam window
    BOOL CALLBACK EnumChildControlsForCE(HWND hwnd, LPARAM lParam) {
        auto* ctx = reinterpret_cast<WindowSearchContext*>(lParam);
        if (!ctx) {
            return FALSE;
        }
        
        wchar_t controlText[256] = { 0 };
        SetLastError(ERROR_SUCCESS);
        const int textLen = GetWindowTextW(
            hwnd, controlText,
            static_cast<int>(sizeof(controlText) / sizeof(controlText[0])));
        if (textLen == 0) {
            const DWORD error = GetLastError();
            if (error != ERROR_SUCCESS) {
                MarkWindowInspectionIncomplete(
                    *ctx, L"GetWindowTextW(child) failed", error);
            }
        }

        if (textLen > 0) {
            std::wstring text = ToLowerCopy(controlText);
            
            // CE-specific UI elements yang sangat khas
            const std::vector<std::wstring> ceUIElements = {
                L"first scan",
                L"next scan",
                L"new scan",
                L"undo scan",
                L"value type",
                L"scan type",
                L"exact value",
                L"4 bytes",
                L"8 bytes",
                L"float",
                L"double",
                L"array of byte",
                L"lua formula",
                L"hex",
                L"address",
                L"memory view",
                L"pointer scan",
                L"dissect data",
                L"auto assemble",
                L"speedhack",
                L"enable speedhack",
                L"bossb" // Modified CE branding
            };
            
            for (const auto& element : ceUIElements) {
                if (text.find(element) != std::wstring::npos) {
                    ctx->suspiciousControlCount++;
#ifdef _DEBUG
                    std::wstring debugMsg = L"[AdvHeuristics] Found CE UI element: " + std::wstring(controlText) + L"\n";
                    OutputDebugStringW(debugMsg.c_str());
#endif
                    // Jika sudah menemukan 3+ CE-specific controls, sangat yakin ini CE
                    if (ctx->suspiciousControlCount >= 3) {
                        ctx->matchedTitle = L"CE_UI_ELEMENTS: Found " + std::to_wstring(ctx->suspiciousControlCount) + L" CE controls";
                        ctx->matched = true;
                        return FALSE; // Stop enumeration
                    }
                    break;
                }
            }
        }
        
        return TRUE;
    }
}

namespace Oblivion {
    // Tentukan apakah process ini perlu di-scan memory-nya
    // Memory scanning hanya untuk process dengan karakteristik mencurigakan
    bool ShouldPerformMemoryScan(const std::wstring& processName) {
        std::wstring lowerName = ::ToLowerCopy(processName);
        
        // Whitelist untuk proses inti Windows
        const std::vector<std::wstring> systemWhitelist = {
            L"system", L"smss.exe", L"csrss.exe", L"wininit.exe", L"services.exe", L"lsass.exe", L"svchost.exe", L"explorer.exe"
        };
        
        // Whitelist untuk proses legitimate dari vendor hardware/software
        const std::vector<std::wstring> legitimatePatterns = {
            L"nvdisplay", L"nvcontainer", L"nvidia", L"nvbackend", L"nvspcap", L"nvstreamer",
            L"amd", L"radeon", L"amdrsserv", L"amddvr",
            L"intel", L"igfx", L"hkcmd",
            L"realtek", L"rthdcpl",
            L"microsoft", L"windows", L"skype", L"teams", L"msedge", L"msedgewebview",
            L"audiodg", L"audio",  // Windows audio services
            L"vcpkgsrv",  // Visual Studio Package Server
            L"adobe", L"acrobat", L"creative cloud",
            L"google", L"chrome", L"drive",
            L"steam", L"origin", L"uplay", L"epicgames", L"battlenet",
            L"discord", L"obs", L"streamlabs",
            L"logitech", L"razer", L"corsair", L"steelseries",
            L"dropbox", L"onedrive", L"icloud",
            L"vscode", L"code.exe", L"cpptools", L"omnisharp",
            L"devenv", L"msbuild", L"cl.exe", L"link.exe"
        };
        
        // Cek whitelist sistem
        for (const auto& pattern : systemWhitelist) {
            if (lowerName == pattern) {
                return false;
            }
        }
        
        // Cek whitelist legitimate (partial match)
        for (const auto& pattern : legitimatePatterns) {
            if (lowerName.find(pattern) != std::wstring::npos) {
                return false;
            }
        }
        
        // Scan semua proses lain
        return true;
    }

    // Heuristik perilaku: deteksi proses dengan aktivitas mencurigakan
    bool IsSuspiciousBehavior(DWORD processId) {
        // Deteksi sederhana: cek apakah proses menggunakan CreateRemoteThread atau WriteProcessMemory
        // (Biasanya digunakan untuk DLL injection atau manipulasi memory)
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
        if (!hProcess) return false;

        HMODULE hMods[1024];
        DWORD cbNeeded;
        bool suspicious = false;
        if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
            for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
                wchar_t szModName[MAX_PATH];
                if (GetModuleBaseNameW(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(wchar_t))) {
                    std::wstring modName = szModName;
                    if (modName.find(L"inject") != std::wstring::npos ||
                        modName.find(L"hook") != std::wstring::npos ||
                        modName.find(L"cheat") != std::wstring::npos) {
                        suspicious = true;
                        break;
                    }
                }
            }
        }
        CloseHandle(hProcess);
        return suspicious;
    }

    void LogSuspiciousProcess(const std::wstring& processName, DWORD processId, const std::string& reason) {
        // Logging/reporting detail untuk proses mencurigakan
        std::wcout << L"[Heuristics] Suspicious process detected: " << processName << L" (PID: " << processId << L") Reason: " << reason.c_str() << std::endl;
        // Integrasi blokir langsung dengan report ke server
        // Build details
        std::wstringstream detailsStream;
        detailsStream << L"Process: " << processName << L" (PID: " << processId << L") | Reason: " << std::wstring(reason.begin(), reason.end());
        // Convert ke UTF-8
        int size_needed = WideCharToMultiByte(CP_UTF8, 0, detailsStream.str().c_str(), (int)detailsStream.str().length(), NULL, 0, NULL, NULL);
        std::string details_utf8;
        if (size_needed > 0) {
            details_utf8.resize(size_needed);
            WideCharToMultiByte(CP_UTF8, 0, detailsStream.str().c_str(), (int)detailsStream.str().length(), &details_utf8[0], size_needed, NULL, NULL);
        }
        // Report dan exit
        ReportViolationAndExit(L"", "ADV_HEURISTIC_DETECTED", details_utf8);
    }

    AdvancedProcessHeuristics::AdvancedProcessHeuristics() : m_heartbeatCallback(nullptr) {}

    AdvancedProcessHeuristics::~AdvancedProcessHeuristics() = default;
    
    void AdvancedProcessHeuristics::SetHeartbeatCallback(std::function<void()> callback) {
        m_heartbeatCallback = callback;
    }

    void AdvancedProcessHeuristics::PerformScan() {
        // Update heartbeat di awal scan
        if (m_heartbeatCallback) {
            m_heartbeatCallback();
        }
        
        // ULTIMATE DETECTION: Handle-Based Heuristics
        // Use the process ID of the host game (current process)
        const DWORD gameProcessId = GetProtectedProcessId();

        // Check for suspicious handles to game process.
        if (gameProcessId != 0) {
            std::wstring suspiciousProcess;
            std::wstring handleScanIssue;
            const HandleScanResult handleScanResult =
                HasSuspiciousHandleToGame(
                    gameProcessId, suspiciousProcess, handleScanIssue);
            if (handleScanResult == HandleScanResult::Suspicious) {
                const auto details = BuildHeuristicDetails(
                    L"Handle-Based Detection",
                    gameProcessId,
                    L"HANDLE_BASED",
                    suspiciousProcess
                );
                ReportViolationAndExit(L"", "ADV_HEURISTIC_DETECTED", details);
            } else if (handleScanResult == HandleScanResult::Incomplete) {
                const std::wstring warning =
                    L"[AdvHeuristics] Handle scan incomplete: " + handleScanIssue;
                OutputDebugStringW(warning.c_str());
                OutputDebugStringW(L"\n");
            }
        }

        // Continue with traditional detection methods
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            const DWORD error = GetLastError();
            ReportViolationAndExit(
                L"", "PROCESS_ENUMERATION_UNAVAILABLE",
                "AdvancedProcessHeuristics: CreateToolhelp32Snapshot failed; error=" +
                    std::to_string(error));
            return;
        }

        PROCESSENTRY32W pe32{};
        pe32.dwSize = sizeof(PROCESSENTRY32W);

        const DWORD selfPid = GetCurrentProcessId();

        if (!Process32FirstW(hSnapshot, &pe32)) {
            const DWORD error = GetLastError();
            CloseHandle(hSnapshot);
            if (error != ERROR_NO_MORE_FILES) {
                ReportViolationAndExit(
                    L"", "PROCESS_ENUMERATION_UNAVAILABLE",
                    "AdvancedProcessHeuristics: Process32FirstW failed; error=" +
                        std::to_string(error));
            }
            return;
        }

        do {
                // Update heartbeat setiap iterasi untuk mencegah timeout
                if (m_heartbeatCallback) {
                    m_heartbeatCallback();
                }
                
                if (pe32.th32ProcessID == 0 || pe32.th32ProcessID == 4 || pe32.th32ProcessID == selfPid) {
                    continue;
                }

                std::wstring processName = pe32.szExeFile;

                // Skip only processes whose whitelist status was positively verified.
                // An incomplete signature/path check must not silently count as trusted.
                std::wstring whitelistIssue;
                const ProcessWhitelistResult whitelistResult =
                    IsProcessWhitelisted(
                        processName, pe32.th32ProcessID, &whitelistIssue);
                if (whitelistResult == ProcessWhitelistResult::Whitelisted) {
                    continue;
                }
                if (whitelistResult == ProcessWhitelistResult::Incomplete) {
                    const std::wstring warning =
                        L"[AdvHeuristics] Signature whitelist check incomplete for " +
                        processName + L" (PID: " +
                        std::to_wstring(pe32.th32ProcessID) + L"): " + whitelistIssue;
                    OutputDebugStringW(warning.c_str());
                    OutputDebugStringW(L"\\n");
                }

#ifdef _DEBUG
                // Debug logging untuk tracking
                std::wstring debugMsg = L"[AdvHeuristics] Scanning process: " + processName + 
                                       L" (PID: " + std::to_wstring(pe32.th32ProcessID) + L")\n";
                OutputDebugStringW(debugMsg.c_str());
#endif

                std::wstring indicator;
                bool hasSuspiciousIndicator = false;

                // Check 1: Suspicious Path Detection.
                std::wstring scanIssue;
                const PathScanResult pathScanResult =
                    HasSuspiciousPath(pe32.th32ProcessID, indicator, scanIssue);
                if (pathScanResult == PathScanResult::Suspicious) {
                    const auto details = BuildHeuristicDetails(
                        processName, pe32.th32ProcessID, L"SUSPICIOUS_PATH", indicator);
                    ReportViolationAndExit(L"", "ADV_HEURISTIC_DETECTED", details);
                } else if (pathScanResult == PathScanResult::Incomplete) {
                    const std::wstring warning =
                        L"[AdvHeuristics] Path scan incomplete for " + processName +
                        L" (PID: " + std::to_wstring(pe32.th32ProcessID) +
                        L"): " + scanIssue;
                    OutputDebugStringW(warning.c_str());
                    OutputDebugStringW(L"\n");
                }

                indicator.clear();

                // Check 2: Suspicious Module (DLL) Detection.
                scanIssue.clear();
                const ModuleScanResult moduleScanResult =
                    ContainsSuspiciousModule(pe32.th32ProcessID, indicator, scanIssue);
                if (moduleScanResult == ModuleScanResult::Suspicious) {
                    const auto details = BuildHeuristicDetails(
                        processName, pe32.th32ProcessID, L"MODULE", indicator);
                    ReportViolationAndExit(L"", "ADV_HEURISTIC_DETECTED", details);
                } else if (moduleScanResult == ModuleScanResult::Incomplete) {
                    const std::wstring warning =
                        L"[AdvHeuristics] Module scan incomplete for " + processName +
                        L" (PID: " + std::to_wstring(pe32.th32ProcessID) +
                        L"): " + scanIssue;
                    OutputDebugStringW(warning.c_str());
                    OutputDebugStringW(L"\n");
                }

                indicator.clear();

                // Check 3: Suspicious Window Class Detection.
                scanIssue.clear();
                const WindowScanResult windowClassResult =
                    HasSuspiciousWindowClass(
                        pe32.th32ProcessID, indicator, scanIssue);
                if (windowClassResult == WindowScanResult::Suspicious) {
                    const auto details = BuildHeuristicDetails(
                        processName, pe32.th32ProcessID, L"WINDOW_CLASS", indicator);
                    ReportViolationAndExit(L"", "ADV_HEURISTIC_DETECTED", details);
                } else if (windowClassResult == WindowScanResult::Incomplete) {
                    const std::wstring warning =
                        L"[AdvHeuristics] Window-class scan incomplete for " + processName +
                        L" (PID: " + std::to_wstring(pe32.th32ProcessID) +
                        L"): " + scanIssue;
                    OutputDebugStringW(warning.c_str());
                    OutputDebugStringW(L"\n");
                }

                indicator.clear();

                // Check 4: Suspicious Window Title Pattern Detection + UI Elements.
                scanIssue.clear();
                const WindowScanResult windowTitleResult =
                    HasSuspiciousWindowTitle(
                        pe32.th32ProcessID, indicator, scanIssue);
                if (windowTitleResult == WindowScanResult::Suspicious) {
                    const auto details = BuildHeuristicDetails(
                        processName, pe32.th32ProcessID, L"WINDOW_TITLE", indicator);
                    ReportViolationAndExit(L"", "ADV_HEURISTIC_DETECTED", details);
                } else if (windowTitleResult == WindowScanResult::Incomplete) {
                    const std::wstring warning =
                        L"[AdvHeuristics] Window-title scan incomplete for " + processName +
                        L" (PID: " + std::to_wstring(pe32.th32ProcessID) +
                        L"): " + scanIssue;
                    OutputDebugStringW(warning.c_str());
                    OutputDebugStringW(L"\n");
                }

                indicator.clear();

                // Check 5: Suspicious Behavior Detection - DISABLED (too many false positives)
                // Behavioral detection seperti handle count tidak reliable karena:
                // - System processes (SearchHost.exe, Chrome, etc) naturally have 500-2000+ handles
                // - No reliable way to differentiate legitimate high handle usage vs malicious
                // 
                // Detection layers 1-4 (DLL + Window Class + Path + Window Title) sudah cukup kuat!
                /*
                if (HasSuspiciousBehavior(pe32.th32ProcessID, indicator)) {
                    const auto details = BuildHeuristicDetails(processName, pe32.th32ProcessID, L"BEHAVIOR", indicator);
                    ReportViolationAndExit(L"", "ADV_HEURISTIC_DETECTED", details);
                }
                */

                indicator.clear();

                // Check 6: Suspicious Memory Signature Detection
                // IMPROVED: Memory scanning sekarang selective - hanya untuk process mencurigakan
                // Dengan signature yang lebih spesifik (DBK driver, CE Lua, Speedhack code)
                // dan whitelist yang ketat untuk menghindari false positive
                if (ShouldPerformMemoryScan(processName)) {
                    std::wstring scanIssue;
                    const MemoryScanResult memoryScanResult =
                        HasSuspiciousMemorySignature(pe32.th32ProcessID, indicator, scanIssue);
                    if (memoryScanResult == MemoryScanResult::Suspicious) {
                        const auto details = BuildHeuristicDetails(processName, pe32.th32ProcessID, L"MEMORY_PATTERN", indicator);
                        ReportViolationAndExit(L"", "ADV_HEURISTIC_DETECTED", details);
                    } else if (memoryScanResult == MemoryScanResult::Incomplete) {
                        const std::wstring warning =
                            L"[AdvHeuristics] Memory scan incomplete for " + processName +
                            L" (PID: " + std::to_wstring(pe32.th32ProcessID) +
                            L"): " + scanIssue;
                        OutputDebugStringW(warning.c_str());
                        OutputDebugStringW(L"\n");
                    }
                }

        } while (Process32NextW(hSnapshot, &pe32));

        const DWORD enumerationError = GetLastError();
        CloseHandle(hSnapshot);

        if (enumerationError != ERROR_NO_MORE_FILES) {
            ReportViolationAndExit(
                L"", "PROCESS_ENUMERATION_UNAVAILABLE",
                "AdvancedProcessHeuristics: Process32NextW failed before enumeration completed; error=" +
                    std::to_string(enumerationError));
        }
    }

    AdvancedProcessHeuristics::ModuleScanResult
    AdvancedProcessHeuristics::ContainsSuspiciousModule(
        DWORD processId,
        std::wstring& matchedModule,
        std::wstring& scanIssue) const {
        scanIssue.clear();

        struct SnapshotHandleDeleter {
            void operator()(HANDLE handle) const noexcept {
                if (handle != INVALID_HANDLE_VALUE && handle != NULL) {
                    CloseHandle(handle);
                }
            }
        };

        HANDLE hModuleSnapshot = INVALID_HANDLE_VALUE;
        DWORD snapshotError = ERROR_SUCCESS;
        constexpr size_t kMaximumSnapshotAttempts = 3;
        for (size_t attempt = 0; attempt < kMaximumSnapshotAttempts; ++attempt) {
            hModuleSnapshot = CreateToolhelp32Snapshot(
                TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
            if (hModuleSnapshot != INVALID_HANDLE_VALUE) {
                break;
            }

            snapshotError = GetLastError();
            if (snapshotError != ERROR_BAD_LENGTH ||
                attempt + 1 == kMaximumSnapshotAttempts) {
                scanIssue = L"CreateToolhelp32Snapshot(module) failed; error=" +
                    std::to_wstring(snapshotError);
                return ModuleScanResult::Incomplete;
            }
        }

        if (hModuleSnapshot == INVALID_HANDLE_VALUE) {
            scanIssue = L"CreateToolhelp32Snapshot(module) did not produce a snapshot";
            return ModuleScanResult::Incomplete;
        }
        std::unique_ptr<void, SnapshotHandleDeleter> snapshotHandle(hModuleSnapshot);

        MODULEENTRY32W moduleEntry{};
        moduleEntry.dwSize = sizeof(moduleEntry);
        SetLastError(ERROR_SUCCESS);
        if (!Module32FirstW(hModuleSnapshot, &moduleEntry)) {
            const DWORD error = GetLastError();
            scanIssue = L"Module32FirstW failed; error=" + std::to_wstring(error);
            return ModuleScanResult::Incomplete;
        }

        do {
            const std::wstring moduleLower = ToLowerCopy(moduleEntry.szModule);
            if (std::find(
                    kSuspiciousModules.begin(),
                    kSuspiciousModules.end(),
                    moduleLower) != kSuspiciousModules.end()) {
                matchedModule = moduleEntry.szModule;
                return ModuleScanResult::Suspicious;
            }

            SetLastError(ERROR_SUCCESS);
        } while (Module32NextW(hModuleSnapshot, &moduleEntry));

        const DWORD enumerationError = GetLastError();
        if (enumerationError != ERROR_NO_MORE_FILES) {
            scanIssue = L"Module32NextW failed before enumeration completed; error=" +
                std::to_wstring(enumerationError);
            return ModuleScanResult::Incomplete;
        }

        return ModuleScanResult::Clean;
    }

    AdvancedProcessHeuristics::WindowScanResult
    AdvancedProcessHeuristics::HasSuspiciousWindowClass(
        DWORD processId,
        std::wstring& matchedClass,
        std::wstring& scanIssue) const {
        scanIssue.clear();
        WindowSearchContext ctx;
        ctx.targetProcessId = processId;
        ctx.searchingTitle = false;

        SetLastError(ERROR_SUCCESS);
        const BOOL enumerationCompleted =
            EnumWindows(EnumWindowsForProcess, reinterpret_cast<LPARAM>(&ctx));

        if (ctx.matched) {
            matchedClass = ctx.matchedClass;
            return WindowScanResult::Suspicious;
        }

        if (!enumerationCompleted) {
            scanIssue = L"EnumWindows stopped before class enumeration completed; error=" +
                std::to_wstring(GetLastError());
            return WindowScanResult::Incomplete;
        }

        if (ctx.incomplete) {
            scanIssue = ctx.scanIssue;
            return WindowScanResult::Incomplete;
        }

        return WindowScanResult::Clean;
    }

    AdvancedProcessHeuristics::WindowScanResult
    AdvancedProcessHeuristics::HasSuspiciousWindowTitle(
        DWORD processId,
        std::wstring& matchedPattern,
        std::wstring& scanIssue) const {
        scanIssue.clear();
        WindowSearchContext ctx;
        ctx.targetProcessId = processId;
        ctx.searchingTitle = true;
        ctx.suspiciousControlCount = 0;

        SetLastError(ERROR_SUCCESS);
        const BOOL topLevelEnumerationCompleted =
            EnumWindows(EnumWindowsForProcess, reinterpret_cast<LPARAM>(&ctx));

        if (ctx.matched) {
            matchedPattern = ctx.matchedTitle;
            return WindowScanResult::Suspicious;
        }

        if (!topLevelEnumerationCompleted) {
            scanIssue =
                L"EnumWindows stopped before title enumeration completed; error=" +
                std::to_wstring(GetLastError());
            ctx.incomplete = true;
        }
        if (ctx.incomplete && scanIssue.empty()) {
            scanIssue = ctx.scanIssue;
        }

        // Also inspect child controls on each window owned by the target process.
        HWND hwnd = NULL;
        do {
            hwnd = FindWindowEx(NULL, hwnd, NULL, NULL);
            if (hwnd != NULL) {
                DWORD windowPid = 0;
                if (GetWindowThreadProcessId(hwnd, &windowPid) == 0) {
                    ctx.incomplete = true;
                    if (ctx.scanIssue.empty()) {
                        ctx.scanIssue = L"GetWindowThreadProcessId failed during child-window search";
                    }
                    continue;
                }

                if (windowPid == processId) {
                    ctx.suspiciousControlCount = 0;
                    SetLastError(ERROR_SUCCESS);
                    const BOOL childEnumerationCompleted = EnumChildWindows(
                        hwnd, EnumChildControlsForCE, reinterpret_cast<LPARAM>(&ctx));

                    if (ctx.matched) {
                        matchedPattern = ctx.matchedTitle;
#ifdef _DEBUG
                        OutputDebugStringW(L"[AdvHeuristics] DETECTED CE by UI elements!\n");
#endif
                        return WindowScanResult::Suspicious;
                    }

                    if (!childEnumerationCompleted) {
                        ctx.incomplete = true;
                        if (ctx.scanIssue.empty()) {
                            ctx.scanIssue =
                                L"EnumChildWindows stopped before child enumeration completed; error=" +
                                std::to_wstring(GetLastError());
                        }
                    }
                }
            }
        } while (hwnd != NULL);

        if (ctx.incomplete) {
            if (scanIssue.empty()) {
                scanIssue = ctx.scanIssue;
            }
            return WindowScanResult::Incomplete;
        }

        return WindowScanResult::Clean;
    }

    AdvancedProcessHeuristics::HandleScanResult
    AdvancedProcessHeuristics::HasSuspiciousHandleToGame(
        DWORD gameProcessId,
        std::wstring& suspiciousProcess,
        std::wstring& scanIssue) const {
        scanIssue.clear();
        bool incomplete = false;

        struct ProcessHandleDeleter {
            void operator()(HANDLE handle) const noexcept {
                if (handle != NULL) {
                    CloseHandle(handle);
                }
            }
        };

        const auto setScanIssue = [&scanIssue](const std::wstring& issue) {
            if (scanIssue.empty()) {
                scanIssue = issue;
            }
        };

        // Querying all system handles is best-effort unless SeDebugPrivilege
        // was actually assigned to this process token.
        if (!EnableDebugPrivilege()) {
            setScanIssue(
                L"SeDebugPrivilege unavailable; error=" + std::to_wstring(GetLastError()));
            incomplete = true;
        }

        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (hNtdll == NULL) {
            setScanIssue(
                L"GetModuleHandleW(ntdll.dll) failed; error=" +
                std::to_wstring(GetLastError()));
            return HandleScanResult::Incomplete;
        }

        NtQuerySystemInformationFn pNtQuerySystemInformation =
            reinterpret_cast<NtQuerySystemInformationFn>(
                GetProcAddress(hNtdll, "NtQuerySystemInformation"));
        if (pNtQuerySystemInformation == NULL) {
            setScanIssue(
                L"NtQuerySystemInformation export unavailable; error=" +
                std::to_wstring(GetLastError()));
            return HandleScanResult::Incomplete;
        }

        const DWORD selfPid = GetCurrentProcessId();
        HANDLE hSelfProcess = OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION, FALSE, selfPid);
        if (hSelfProcess == NULL) {
            setScanIssue(
                L"OpenProcess for scanner process failed; error=" +
                std::to_wstring(GetLastError()));
            return HandleScanResult::Incomplete;
        }
        std::unique_ptr<void, ProcessHandleDeleter> selfProcessHandle(hSelfProcess);

        const ULONG_PTR selfHandleValue =
            reinterpret_cast<ULONG_PTR>(hSelfProcess);
        if (selfHandleValue > (std::numeric_limits<USHORT>::max)()) {
            setScanIssue(L"scanner process handle exceeds legacy handle-table representation");
            return HandleScanResult::Incomplete;
        }
        const USHORT selfHandleEntry =
            static_cast<USHORT>(selfHandleValue);

        constexpr ULONG kInitialBufferSize = 0x10000;
        constexpr ULONG kMaximumBufferSize = 128u * 1024u * 1024u;
        constexpr size_t kMaximumQueryAttempts = 16;
        ULONG bufferSize = kInitialBufferSize;
        ULONG returnLength = 0;
        NTSTATUS status = STATUS_INFO_LENGTH_MISMATCH;
        bool querySucceeded = false;
        std::vector<BYTE> buffer;

        try {
            for (size_t attempt = 0; attempt < kMaximumQueryAttempts; ++attempt) {
                buffer.resize(bufferSize);
                returnLength = 0;
                status = pNtQuerySystemInformation(
                    SYSTEM_HANDLE_INFORMATION_CLASS,
                    buffer.data(),
                    bufferSize,
                    &returnLength);

                if (status == 0) {
                    querySucceeded = true;
                    break;
                }

                if (status != STATUS_INFO_LENGTH_MISMATCH) {
                    setScanIssue(
                        L"NtQuerySystemInformation failed; status=" +
                        std::to_wstring(static_cast<unsigned long>(status)));
                    return HandleScanResult::Incomplete;
                }

                if (attempt + 1 == kMaximumQueryAttempts) {
                    break;
                }

                ULONG nextBufferSize = 0;
                if (returnLength > bufferSize) {
                    if (returnLength > kMaximumBufferSize) {
                        setScanIssue(L"system handle table exceeds the 128 MiB scan limit");
                        return HandleScanResult::Incomplete;
                    }

                    const ULONG remainingCapacity = kMaximumBufferSize - returnLength;
                    const ULONG extraCapacity = (std::min)(static_cast<ULONG>(0x1000), remainingCapacity);
                    nextBufferSize = returnLength + extraCapacity;
                } else {
                    nextBufferSize = bufferSize <= kMaximumBufferSize / 2
                        ? bufferSize * 2
                        : kMaximumBufferSize;
                }

                if (nextBufferSize <= bufferSize ||
                    nextBufferSize > kMaximumBufferSize) {
                    setScanIssue(L"system handle query buffer cannot grow within its limit");
                    return HandleScanResult::Incomplete;
                }

                bufferSize = nextBufferSize;
            }
        } catch (const std::bad_alloc&) {
            setScanIssue(L"system handle query buffer allocation failed");
            return HandleScanResult::Incomplete;
        }

        if (!querySucceeded) {
            setScanIssue(L"system handle query exceeded its retry limit");
            return HandleScanResult::Incomplete;
        }

        constexpr size_t kHandleArrayOffset =
            offsetof(SYSTEM_HANDLE_INFORMATION, Handles);
        if (returnLength < kHandleArrayOffset || returnLength > buffer.size()) {
            setScanIssue(L"NtQuerySystemInformation returned an invalid buffer length");
            return HandleScanResult::Incomplete;
        }

        PSYSTEM_HANDLE_INFORMATION handleInfo =
            reinterpret_cast<PSYSTEM_HANDLE_INFORMATION>(buffer.data());
        const size_t availableHandleCount =
            (static_cast<size_t>(returnLength) - kHandleArrayOffset) /
            sizeof(SYSTEM_HANDLE);
        if (handleInfo->HandleCount > availableHandleCount) {
            setScanIssue(L"system handle count exceeds the returned buffer length");
            return HandleScanResult::Incomplete;
        }

        // ObjectTypeNumber is a runtime index, not a stable constant. Resolve the
        // process-object index from our own known process handle in this snapshot.
        BYTE processObjectType = 0;
        bool foundSelfProcessHandle = false;
        for (ULONG i = 0; i < handleInfo->HandleCount; ++i) {
            const SYSTEM_HANDLE& handle = handleInfo->Handles[i];
            if (handle.ProcessId == selfPid && handle.Handle == selfHandleEntry) {
                processObjectType = handle.ObjectTypeNumber;
                foundSelfProcessHandle = true;
                break;
            }
        }
        if (!foundSelfProcessHandle) {
            setScanIssue(L"scanner process handle is absent from the system handle snapshot");
            return HandleScanResult::Incomplete;
        }

        const ACCESS_MASK dangerousMasks =
            PROCESS_VM_READ |
            PROCESS_VM_WRITE |
            PROCESS_VM_OPERATION;

        for (ULONG i = 0; i < handleInfo->HandleCount; ++i) {
            const SYSTEM_HANDLE& handle = handleInfo->Handles[i];

            if (handle.ProcessId == gameProcessId ||
                handle.ProcessId == 0 ||
                handle.ProcessId == 4 ||
                handle.ProcessId == selfPid) {
                continue;
            }

            if (handle.ObjectTypeNumber != processObjectType ||
                (handle.GrantedAccess & dangerousMasks) == 0) {
                continue;
            }

            const std::wstring processName = GetProcessName(handle.ProcessId);
            if (!processName.empty()) {
                std::wstring whitelistIssue;
                const ProcessWhitelistResult whitelistResult =
                    IsProcessWhitelisted(
                        processName, handle.ProcessId, &whitelistIssue);
                if (whitelistResult == ProcessWhitelistResult::Whitelisted) {
                    continue;
                }
                if (whitelistResult == ProcessWhitelistResult::Incomplete) {
                    setScanIssue(
                        L"signature whitelist check incomplete for handle owner PID " +
                        std::to_wstring(handle.ProcessId) + L": " + whitelistIssue);
                    incomplete = true;
                }
            }

            HANDLE hOwnerProcess =
                OpenProcess(PROCESS_DUP_HANDLE, FALSE, handle.ProcessId);
            if (hOwnerProcess == NULL) {
                setScanIssue(
                    L"OpenProcess(PROCESS_DUP_HANDLE) failed; error=" +
                    std::to_wstring(GetLastError()));
                incomplete = true;
                continue;
            }
            std::unique_ptr<void, ProcessHandleDeleter> ownerHandle(hOwnerProcess);

            HANDLE hDuplicated = NULL;
            if (!DuplicateHandle(
                    hOwnerProcess,
                    reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(handle.Handle)),
                    GetCurrentProcess(),
                    &hDuplicated,
                    0,
                    FALSE,
                    DUPLICATE_SAME_ACCESS)) {
                setScanIssue(
                    L"DuplicateHandle failed; error=" + std::to_wstring(GetLastError()));
                incomplete = true;
                continue;
            }
            std::unique_ptr<void, ProcessHandleDeleter> duplicatedHandle(hDuplicated);

            const DWORD targetPid = GetProcessId(hDuplicated);
            if (targetPid == 0) {
                setScanIssue(
                    L"GetProcessId on duplicated handle failed; error=" +
                    std::to_wstring(GetLastError()));
                incomplete = true;
                continue;
            }

            if (targetPid == gameProcessId) {
                std::wstring ownerName = processName.empty()
                    ? L"UNKNOWN_PROCESS"
                    : processName;
                suspiciousProcess = ownerName + L" (PID:" +
                    std::to_wstring(handle.ProcessId) +
                    L", Access:0x" + std::to_wstring(handle.GrantedAccess) + L")";
#ifdef _DEBUG
                std::wstring debugMsg =
                    L"[AdvHeuristics] DETECTED SUSPICIOUS HANDLE to game: " +
                    suspiciousProcess + L"\n";
                OutputDebugStringW(debugMsg.c_str());
#endif
                return HandleScanResult::Suspicious;
            }
        }

        return incomplete ? HandleScanResult::Incomplete : HandleScanResult::Clean;
    }

    AdvancedProcessHeuristics::PathScanResult AdvancedProcessHeuristics::HasSuspiciousPath(
        DWORD processId,
        std::wstring& matchedPath,
        std::wstring& scanIssue) const {
        scanIssue.clear();
        std::wstring fullPath;
        DWORD pathError = ERROR_SUCCESS;
        if (!GetProcessImagePath(processId, fullPath, &pathError)) {
            scanIssue = L"QueryFullProcessImageNameW failed; error=" +
                std::to_wstring(pathError);
            return PathScanResult::Incomplete;
        }

        const std::wstring lowerPath = ToLowerCopy(fullPath);

#ifdef _DEBUG
        std::wstring debugMsg = L"[AdvHeuristics] Process path: " + fullPath + L"\n";
        OutputDebugStringW(debugMsg.c_str());
#endif

        // Suspicious path keywords
        const std::vector<std::wstring> suspiciousPathKeywords = {
            L"cheat",
            L"hack",
            L"\\ce\\",
            L"\\ce2",
            L"\\cheatengine",
            L"\\newce",
            L"cheatprogram",
            L"trainer",
            L"crack",
            L"keygen",
            L"patch",
            L"mod\\",
            L"inject",
            L"\\bossb",
            L"\\ce7",
            L"\\ce6",
            L"memory scanner",
            L"memoryscanner"
        };

        for (const auto& keyword : suspiciousPathKeywords) {
            if (lowerPath.find(keyword) != std::wstring::npos) {
                matchedPath = L"SUSPICIOUS_PATH: " + fullPath;
#ifdef _DEBUG
                std::wstring debugMsg2 = L"[AdvHeuristics] DETECTED SUSPICIOUS PATH with keyword: " + keyword + L"\n";
                OutputDebugStringW(debugMsg2.c_str());
#endif
                return PathScanResult::Suspicious;
            }
        }

        return PathScanResult::Clean;
    }

    bool AdvancedProcessHeuristics::HasSuspiciousBehavior(DWORD processId, std::wstring& behaviorType) const {
        // DISABLED: Behavioral detection terlalu prone to false positive
        // System processes seperti SearchHost.exe, Chrome.exe, dll bisa punya 500+ handles
        // dan ini normal behavior untuk software yang complex.
        // 
        // Alternative approach: Kombinasi dengan indicator lain (DLL, window class, window title)
        // sudah cukup kuat untuk mendeteksi CE tanpa perlu behavioral detection.
        //
        // Jika ingin menggunakan behavioral detection, perlu:
        // 1. Threshold yang jauh lebih tinggi (>1000 handles)
        // 2. Kombinasi dengan additional checks (ReadProcessMemory call tracking, etc)
        // 3. Machine learning untuk pattern recognition
        
        return false;
        
        /* ORIGINAL CODE - DISABLED
        // Buka handle ke process
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
        if (hProcess == NULL) {
            return false;
        }

        bool detected = false;
        DWORD handleCount = 0;

        // Check 1: Handle Count - CE biasanya membuka banyak handle ke process lain
        if (GetProcessHandleCount(hProcess, &handleCount)) {
            // CE typically has 500+ handles when actively scanning/attached
            // Naikkan threshold untuk menghindari false positive
            if (handleCount > 800) {
                // Verifikasi lebih lanjut: cek apakah ada handle ke process lain
                // Ini adalah indikasi kuat bahwa process sedang mengakses memory process lain
                DWORD currentSessionId = 0;
                ProcessIdToSessionId(GetCurrentProcessId(), &currentSessionId);
                
                DWORD targetSessionId = 0;
                if (ProcessIdToSessionId(processId, &targetSessionId) && targetSessionId == currentSessionId) {
                    behaviorType = L"HIGH_HANDLE_COUNT: " + std::to_wstring(handleCount);
                    detected = true;
                }
            }
        }

        CloseHandle(hProcess);
        return detected;
        */
    }

    AdvancedProcessHeuristics::MemoryScanResult
    AdvancedProcessHeuristics::HasSuspiciousMemorySignature(
        DWORD processId,
        std::wstring& matchedPattern,
        std::wstring& scanIssue) const {
        scanIssue.clear();

        HANDLE hProcess = OpenProcess(
            PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, processId);
        if (hProcess == NULL) {
            scanIssue = L"OpenProcess failed; error=" + std::to_wstring(GetLastError());
            return MemoryScanResult::Incomplete;
        }

        struct ProcessHandleDeleter {
            void operator()(HANDLE handle) const noexcept {
                if (handle != NULL) {
                    CloseHandle(handle);
                }
            }
        };
        std::unique_ptr<void, ProcessHandleDeleter> processHandle(hProcess);

        BOOL scannerIsWow64 = FALSE;
        BOOL targetIsWow64 = FALSE;
        if (!IsWow64Process(GetCurrentProcess(), &scannerIsWow64)) {
            scanIssue = L"IsWow64Process failed for scanner; error=" +
                std::to_wstring(GetLastError());
            return MemoryScanResult::Incomplete;
        }
        if (!IsWow64Process(hProcess, &targetIsWow64)) {
            scanIssue = L"IsWow64Process failed for target; error=" +
                std::to_wstring(GetLastError());
            return MemoryScanResult::Incomplete;
        }
        const bool scannerHasNarrowerAddressSpace =
            scannerIsWow64 && !targetIsWow64;

        constexpr size_t kChunkSize = 1024 * 1024;
        constexpr size_t kMaxTotalScan = 100 * 1024 * 1024;
        size_t totalScanned = 0;
        size_t maxPatternSize = 0;
        for (const auto& signature : kMemorySignatures) {
            maxPatternSize = (std::max)(maxPatternSize, signature.patternSize);
        }

        std::vector<BYTE> carry;
        ULONG_PTR queryAddress = 0;

        try {
            // VirtualQueryEx walks the target address space by complete regions.
            // ERROR_INVALID_PARAMETER is the documented end-of-address-space result.
            for (;;) {
                MEMORY_BASIC_INFORMATION mbi{};
                SetLastError(ERROR_SUCCESS);
                const SIZE_T querySize = VirtualQueryEx(
                    hProcess,
                    reinterpret_cast<LPCVOID>(queryAddress),
                    &mbi,
                    sizeof(mbi));

                if (querySize == 0) {
                    const DWORD error = GetLastError();
                    if (error == ERROR_INVALID_PARAMETER) {
                        if (scannerHasNarrowerAddressSpace) {
                            scanIssue =
                                L"32-bit WOW64 client cannot verify the complete 64-bit target address space";
                            return MemoryScanResult::Incomplete;
                        }
                        break;
                    }

                    scanIssue = L"VirtualQueryEx failed; error=" + std::to_wstring(error);
                    return MemoryScanResult::Incomplete;
                }

                if (querySize != sizeof(mbi) || mbi.RegionSize == 0) {
                    scanIssue = L"VirtualQueryEx returned an invalid memory region";
                    return MemoryScanResult::Incomplete;
                }

                const ULONG_PTR regionBase = reinterpret_cast<ULONG_PTR>(mbi.BaseAddress);
                const ULONG_PTR maxAddress = (std::numeric_limits<ULONG_PTR>::max)();
                if (regionBase > queryAddress ||
                    mbi.RegionSize > maxAddress - regionBase) {
                    scanIssue = L"VirtualQueryEx returned an overflowing or non-progressing region";
                    return MemoryScanResult::Incomplete;
                }

                const ULONG_PTR regionEnd = regionBase + mbi.RegionSize;
                if (regionEnd <= queryAddress) {
                    scanIssue = L"VirtualQueryEx did not advance the address-space cursor";
                    return MemoryScanResult::Incomplete;
                }

                const DWORD protection = mbi.Protect & 0xFF;
                const bool isExecutable =
                    protection == PAGE_EXECUTE_READ ||
                    protection == PAGE_EXECUTE_READWRITE ||
                    protection == PAGE_EXECUTE_WRITECOPY;
                const bool isReadable =
                    protection == PAGE_READWRITE ||
                    protection == PAGE_WRITECOPY ||
                    protection == PAGE_READONLY ||
                    isExecutable;

                if (mbi.State == MEM_COMMIT &&
                    isReadable &&
                    !(mbi.Protect & PAGE_GUARD) &&
                    !(mbi.Protect & PAGE_NOACCESS)) {
                    ULONG_PTR scanAddress = queryAddress;
                    carry.clear();

                    while (scanAddress < regionEnd) {
                        if (totalScanned >= kMaxTotalScan) {
                            scanIssue = L"per-process memory scan budget reached";
                            return MemoryScanResult::Incomplete;
                        }

                        const size_t regionRemaining =
                            static_cast<size_t>(regionEnd - scanAddress);
                        const size_t budgetRemaining = kMaxTotalScan - totalScanned;
                        const size_t requestSize = (std::min)(
                            (std::min)(regionRemaining, kChunkSize),
                            budgetRemaining);
                        if (requestSize == 0) {
                            scanIssue = L"memory scan made no progress";
                            return MemoryScanResult::Incomplete;
                        }

                        std::vector<BYTE> buffer(requestSize);
                        SIZE_T bytesRead = 0;
                        const BOOL readSucceeded = ReadProcessMemory(
                            hProcess,
                            reinterpret_cast<LPCVOID>(scanAddress),
                            buffer.data(),
                            requestSize,
                            &bytesRead);
                        const DWORD readError =
                            readSucceeded ? ERROR_SUCCESS : GetLastError();

                        if (bytesRead > requestSize) {
                            scanIssue = L"ReadProcessMemory returned an invalid byte count";
                            return MemoryScanResult::Incomplete;
                        }

                        if (bytesRead > 0) {
                            // Carry the end of the previous chunk so signatures crossing
                            // a chunk boundary are not missed.
                            std::vector<BYTE> scanBuffer;
                            scanBuffer.reserve(carry.size() + bytesRead);
                            scanBuffer.insert(scanBuffer.end(), carry.begin(), carry.end());
                            scanBuffer.insert(
                                scanBuffer.end(), buffer.begin(), buffer.begin() + bytesRead);

                            for (const auto& signature : kMemorySignatures) {
                                if (signature.patternSize == 0 ||
                                    signature.patternSize > scanBuffer.size() ||
                                    (signature.requiresExecutableMemory && !isExecutable)) {
                                    continue;
                                }

                                for (size_t i = 0;
                                     i <= scanBuffer.size() - signature.patternSize;
                                     ++i) {
                                    bool match = true;
                                    for (size_t j = 0; j < signature.patternSize; ++j) {
                                        if ((scanBuffer[i + j] & signature.mask[j]) !=
                                            (signature.pattern[j] & signature.mask[j])) {
                                            match = false;
                                            break;
                                        }
                                    }

                                    if (match) {
                                        matchedPattern = signature.name;
                                        return MemoryScanResult::Suspicious;
                                    }
                                }
                            }

                            if (maxPatternSize > 1) {
                                const size_t carrySize = (std::min)(
                                    maxPatternSize - 1, scanBuffer.size());
                                carry.assign(
                                    scanBuffer.end() - carrySize, scanBuffer.end());
                            }
                            totalScanned += bytesRead;
                        }

                        if (!readSucceeded || bytesRead != requestSize) {
                            scanIssue =
                                L"ReadProcessMemory returned an incomplete region read; error=" +
                                std::to_wstring(readError);
                            return MemoryScanResult::Incomplete;
                        }

                        scanAddress += static_cast<ULONG_PTR>(requestSize);
                    }
                } else {
                    carry.clear();
                }

                queryAddress = regionEnd;
            }
        } catch (const std::bad_alloc&) {
            scanIssue = L"memory scan buffer allocation failed";
            return MemoryScanResult::Incomplete;
        }

        return MemoryScanResult::Clean;
    }

    std::string AdvancedProcessHeuristics::BuildHeuristicDetails(const std::wstring& processName,
        DWORD processId,
        const std::wstring& detectionType,
        const std::wstring& indicator) const {
        std::wstringstream wss;
        wss << L"[" << detectionType << L"] " << processName << L" (PID:" << processId << L") => " << indicator;
        return ConvertWideToUtf8(wss.str());
    }

    std::string AdvancedProcessHeuristics::ConvertWideToUtf8(const std::wstring& input) const {
        if (input.empty()) {
            return std::string();
        }

        if (input.size() > static_cast<size_t>((std::numeric_limits<int>::max)())) {
            return std::string();
        }

        const int inputLength = static_cast<int>(input.size());
        const int sizeNeeded = WideCharToMultiByte(
            CP_UTF8, WC_ERR_INVALID_CHARS, input.c_str(), inputLength,
            nullptr, 0, nullptr, nullptr);
        if (sizeNeeded <= 0) {
            return std::string();
        }

        // The explicit input length excludes a trailing NUL, so allocate exactly
        // the byte count returned by the sizing call. This avoids writing the
        // terminator past a sizeNeeded - 1 string allocation.
        std::string result(static_cast<size_t>(sizeNeeded), '\\0');
        const int converted = WideCharToMultiByte(
            CP_UTF8, WC_ERR_INVALID_CHARS, input.c_str(), inputLength,
            &result[0], sizeNeeded, nullptr, nullptr);
        if (converted != sizeNeeded) {
            return std::string();
        }

        return result;
    }
}

