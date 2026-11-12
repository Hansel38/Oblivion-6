#include "pch.h"
#include "advanced_process_heuristics.h"
#include "digital_signature_validator.h"
#include <tlhelp32.h>
#include <vector>
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
        bool matched = false;
        bool searchingTitle = false; // true = searching for title patterns, false = searching for class
        int suspiciousControlCount = 0; // Count of suspicious child controls (for UI element detection)
    };

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
        // Cheat Engine main forms (Lazarus/FPC classes)
        L"tceform",
        L"tcemainform",
        L"tcheatengine",
        L"tform1",           // Generic Lazarus form - CE sometimes uses this
        L"tmainform",        // Another generic CE main form name
        
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
        
        // x64dbg
        L"qt5qwindowicon",
        L"qt5qwindowowndc",
        L"x64dbgmain",
        
        // OllyDbg variants
        L"ollydbg",
        L"odbg",
        
        // IDA Pro
        L"idawindow",
        L"qt5156qwindowicon",
        
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

    // Fungsi helper untuk mendapatkan full path dari process
    std::wstring GetProcessPath(DWORD processId) {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
        if (hProcess == NULL) {
            return L"";
        }

        wchar_t processPath[MAX_PATH] = { 0 };
        DWORD size = MAX_PATH;
        std::wstring result;

        if (QueryFullProcessImageNameW(hProcess, 0, processPath, &size)) {
            result = processPath;
        }

        CloseHandle(hProcess);
        return result;
    }

    bool IsProcessWhitelisted(const std::wstring& processName, DWORD processId = 0) {
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
            return false; // Tidak ada di whitelist
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
            return true;
        }
        
        // Proses memerlukan verifikasi signature - cegah spoofing!
        if (processId == 0) {
            // Jika PID tidak diberikan, tidak bisa verifikasi - anggap tidak aman
            return false;
        }
        
        // Dapatkan full path dari process
        std::wstring processPath = GetProcessPath(processId);
        if (processPath.empty()) {
            // Tidak bisa mendapatkan path - suspicious
            std::wcout << L"[AdvHeuristics] WARNING: Cannot get path for whitelisted process: " << processName << L" (PID: " << processId << L")" << std::endl;
            return false;
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
            
            return cachedResult;
        }
        
        // Dapatkan expected publisher dari DigitalSignatureValidator
        const auto& publisherMap = Oblivion::DigitalSignatureValidator::m_expectedPublishers;
        auto it = publisherMap.find(lowerName);
        
        if (it == publisherMap.end()) {
            // Tidak ada expected publisher - ini seharusnya tidak terjadi karena kita sudah filter di atas
            std::wcout << L"[AdvHeuristics] WARNING: No expected publisher for: " << processName << std::endl;
            return false;
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
            
            return false; // Tidak akan tercapai karena ReportViolationAndExit memanggil ExitProcess
        }
        
        // Signature verified successfully
        std::wcout << L"[AdvHeuristics] Signature verified: " << processName 
               << L" (PID: " << processId << L") - Publisher: " << expectedPublisher << std::endl;
        return true;
    }

    // Enable SeDebugPrivilege untuk akses system-wide handles
    bool EnableDebugPrivilege() {
        HANDLE hToken = NULL;
        TOKEN_PRIVILEGES tokenPrivileges;
        LUID luid;

        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
            return false;
        }

        if (!LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &luid)) {
            CloseHandle(hToken);
            return false;
        }

        tokenPrivileges.PrivilegeCount = 1;
        tokenPrivileges.Privileges[0].Luid = luid;
        tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        bool result = AdjustTokenPrivileges(hToken, FALSE, &tokenPrivileges, 0, NULL, NULL) != 0;
        CloseHandle(hToken);
        return result;
    }

    // Get process name from PID
    std::wstring GetProcessName(DWORD processId) {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
        if (hProcess == NULL) {
            return L"";
        }

        wchar_t processName[MAX_PATH] = { 0 };
        DWORD size = MAX_PATH;
        std::wstring result;

        if (QueryFullProcessImageNameW(hProcess, 0, processName, &size)) {
            // Extract filename from full path
            std::wstring fullPath(processName);
            size_t lastSlash = fullPath.find_last_of(L"\\/");
            if (lastSlash != std::wstring::npos) {
                result = fullPath.substr(lastSlash + 1);
            } else {
                result = fullPath;
            }
        }

        CloseHandle(hProcess);
        return result;
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
        GetWindowThreadProcessId(hwnd, &windowProcessId);
        if (windowProcessId != ctx->targetProcessId) {
            return TRUE;
        }

        if (ctx->searchingTitle) {
            // Search for suspicious window titles
            wchar_t windowTitle[512] = { 0 };
            const int titleLen = GetWindowTextW(hwnd, windowTitle, static_cast<int>(sizeof(windowTitle) / sizeof(windowTitle[0])));
            
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
            const int len = GetClassNameW(hwnd, className, static_cast<int>(sizeof(className) / sizeof(className[0])));
            if (len == 0) {
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
        const int textLen = GetWindowTextW(hwnd, controlText, static_cast<int>(sizeof(controlText) / sizeof(controlText[0])));
        
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

        // Check for suspicious handles to game process (ULTIMATE - detects ANY memory scanner)
        if (gameProcessId != 0) {
            std::wstring suspiciousProcess;
            if (HasSuspiciousHandleToGame(gameProcessId, suspiciousProcess)) {
                const auto details = BuildHeuristicDetails(
                    L"Handle-Based Detection",
                    gameProcessId,
                    L"HANDLE_BASED",
                    suspiciousProcess
                );
                ReportViolationAndExit(L"", "ADV_HEURISTIC_DETECTED", details);
            }
        }

        // Continue with traditional detection methods
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            return;
        }

        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32W);

        const DWORD selfPid = GetCurrentProcessId();

        if (Process32FirstW(hSnapshot, &pe32)) {
            do {
                // Update heartbeat setiap iterasi untuk mencegah timeout
                if (m_heartbeatCallback) {
                    m_heartbeatCallback();
                }
                
                if (pe32.th32ProcessID == 0 || pe32.th32ProcessID == 4 || pe32.th32ProcessID == selfPid) {
                    continue;
                }

                std::wstring processName = pe32.szExeFile;

                // Skip whitelisted system processes untuk menghindari false positive
                // IMPORTANT: Sekarang dengan signature verification untuk mencegah spoofing
                if (IsProcessWhitelisted(processName, pe32.th32ProcessID)) {
                    continue;
                }

#ifdef _DEBUG
                // Debug logging untuk tracking
                std::wstring debugMsg = L"[AdvHeuristics] Scanning process: " + processName + 
                                       L" (PID: " + std::to_wstring(pe32.th32ProcessID) + L")\n";
                OutputDebugStringW(debugMsg.c_str());
#endif

                std::wstring indicator;
                bool hasSuspiciousIndicator = false;

                // Check 1: Suspicious Path Detection (Priority #1 - Most reliable for this case)
                // Deteksi path mencurigakan seperti "cheatprogram", "newce", "hack", dll
                if (HasSuspiciousPath(pe32.th32ProcessID, indicator)) {
                    const auto details = BuildHeuristicDetails(processName, pe32.th32ProcessID, L"SUSPICIOUS_PATH", indicator);
                    ReportViolationAndExit(L"", "ADV_HEURISTIC_DETECTED", details);
                }

                indicator.clear();

                // Check 2: Suspicious Module (DLL) Detection
                if (ContainsSuspiciousModule(pe32.th32ProcessID, indicator)) {
                    const auto details = BuildHeuristicDetails(processName, pe32.th32ProcessID, L"MODULE", indicator);
                    ReportViolationAndExit(L"", "ADV_HEURISTIC_DETECTED", details);
                }

                indicator.clear();

                // Check 3: Suspicious Window Class Detection
                if (HasSuspiciousWindowClass(pe32.th32ProcessID, indicator)) {
                    const auto details = BuildHeuristicDetails(processName, pe32.th32ProcessID, L"WINDOW_CLASS", indicator);
                    ReportViolationAndExit(L"", "ADV_HEURISTIC_DETECTED", details);
                }

                indicator.clear();

                // Check 4: Suspicious Window Title Pattern Detection + UI Elements
                // CRITICAL: Deteksi pattern window title khas CE seperti "00001C0C-Republic-RO"
                // ATAU deteksi CE-specific UI controls seperti "First Scan", "Next Scan", dll
                if (HasSuspiciousWindowTitle(pe32.th32ProcessID, indicator)) {
                    const auto details = BuildHeuristicDetails(processName, pe32.th32ProcessID, L"WINDOW_TITLE", indicator);
                    ReportViolationAndExit(L"", "ADV_HEURISTIC_DETECTED", details);
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
                    if (HasSuspiciousMemorySignature(pe32.th32ProcessID, indicator)) {
                        const auto details = BuildHeuristicDetails(processName, pe32.th32ProcessID, L"MEMORY_PATTERN", indicator);
                        ReportViolationAndExit(L"", "ADV_HEURISTIC_DETECTED", details);
                    }
                }

            } while (Process32NextW(hSnapshot, &pe32));
        }

        CloseHandle(hSnapshot);
    }

    bool AdvancedProcessHeuristics::ContainsSuspiciousModule(DWORD processId, std::wstring& matchedModule) const {
        HANDLE hModuleSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
        if (hModuleSnapshot == INVALID_HANDLE_VALUE) {
            return false;
        }

        MODULEENTRY32W me32;
        me32.dwSize = sizeof(MODULEENTRY32W);

        bool detected = false;

        if (Module32FirstW(hModuleSnapshot, &me32)) {
            do {
                std::wstring moduleLower = ToLowerCopy(me32.szModule);
                if (std::find(kSuspiciousModules.begin(), kSuspiciousModules.end(), moduleLower) != kSuspiciousModules.end()) {
                    matchedModule = me32.szModule;
                    detected = true;
                    break;
                }
            } while (Module32NextW(hModuleSnapshot, &me32));
        }

        CloseHandle(hModuleSnapshot);
        return detected;
    }

    bool AdvancedProcessHeuristics::HasSuspiciousWindowClass(DWORD processId, std::wstring& matchedClass) const {
        WindowSearchContext ctx;
        ctx.targetProcessId = processId;
        ctx.searchingTitle = false;

        EnumWindows(EnumWindowsForProcess, reinterpret_cast<LPARAM>(&ctx));

        if (!ctx.matched) {
            return false;
        }

        matchedClass = ctx.matchedClass;
        return true;
    }

    bool AdvancedProcessHeuristics::HasSuspiciousWindowTitle(DWORD processId, std::wstring& matchedPattern) const {
        WindowSearchContext ctx;
        ctx.targetProcessId = processId;
        ctx.searchingTitle = true;
        ctx.suspiciousControlCount = 0;

        // First, try to detect by window title
        EnumWindows(EnumWindowsForProcess, reinterpret_cast<LPARAM>(&ctx));

        if (ctx.matched) {
            matchedPattern = ctx.matchedTitle;
            return true;
        }

        // If not found by title, enumerate all windows of this process
        // and check their child controls for CE-specific UI elements
        HWND hwnd = NULL;
        do {
            hwnd = FindWindowEx(NULL, hwnd, NULL, NULL);
            if (hwnd != NULL) {
                DWORD windowPID = 0;
                GetWindowThreadProcessId(hwnd, &windowPID);
                
                if (windowPID == processId) {
                    // Found a window belonging to target process
                    // Enumerate its child controls
                    ctx.suspiciousControlCount = 0;
                    EnumChildWindows(hwnd, EnumChildControlsForCE, reinterpret_cast<LPARAM>(&ctx));
                    
                    if (ctx.matched) {
                        matchedPattern = ctx.matchedTitle;
#ifdef _DEBUG
                        OutputDebugStringW(L"[AdvHeuristics] DETECTED CE by UI elements!\n");
#endif
                        return true;
                    }
                }
            }
        } while (hwnd != NULL);

        return false;
    }

    bool AdvancedProcessHeuristics::HasSuspiciousHandleToGame(DWORD gameProcessId, std::wstring& suspiciousProcess) const {
        // Enable SeDebugPrivilege untuk akses system-wide handles
        EnableDebugPrivilege();

        // Load NtQuerySystemInformation dari ntdll.dll
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (hNtdll == NULL) {
            return false;
        }

        NtQuerySystemInformationFn pNtQuerySystemInformation =
            reinterpret_cast<NtQuerySystemInformationFn>(
                GetProcAddress(hNtdll, "NtQuerySystemInformation"));
        if (pNtQuerySystemInformation == NULL) {
            return false;
        }

        // Query system handles - start dengan buffer kecil, expand jika perlu
        ULONG bufferSize = 0x10000; // 64KB initial
        std::vector<BYTE> buffer;
        NTSTATUS status;

        do {
            buffer.resize(bufferSize);
            ULONG returnLength = 0;
            status = pNtQuerySystemInformation(
                SYSTEM_HANDLE_INFORMATION_CLASS,
                buffer.data(),
                bufferSize,
                &returnLength);

            if (status == STATUS_INFO_LENGTH_MISMATCH) {
                bufferSize = returnLength + 0x1000; // Add extra space
            }
        } while (status == STATUS_INFO_LENGTH_MISMATCH);

        if (status != 0) {
            return false;
        }

        PSYSTEM_HANDLE_INFORMATION handleInfo = reinterpret_cast<PSYSTEM_HANDLE_INFORMATION>(buffer.data());
        const DWORD selfPid = GetCurrentProcessId();

        // Dangerous access masks untuk memory manipulation
        // Minimal: PROCESS_VM_READ sudah cukup untuk memory scanner
        const ACCESS_MASK dangerousMasks = 
            PROCESS_VM_READ |           // Read memory (required for scanning)
            PROCESS_VM_WRITE |          // Write memory (required for modification)
            PROCESS_VM_OPERATION;       // VirtualProtect, VirtualAlloc (required for advanced manipulation)

        // Iterate through all handles
        for (ULONG i = 0; i < handleInfo->HandleCount; ++i) {
            const SYSTEM_HANDLE& handle = handleInfo->Handles[i];

            // Skip handles owned by game process itself or system processes
            if (handle.ProcessId == gameProcessId || 
                handle.ProcessId == 0 || 
                handle.ProcessId == 4 || 
                handle.ProcessId == selfPid) {
                continue;
            }

            // Check if this handle points to a process object (ObjectTypeNumber 7)
            // AND has dangerous access rights
            if (handle.ObjectTypeNumber == 7 && (handle.GrantedAccess & dangerousMasks) != 0) {
                // Get process name that owns this suspicious handle
                std::wstring processName = GetProcessName(handle.ProcessId);
                
                if (!processName.empty() && !IsProcessWhitelisted(processName, handle.ProcessId)) {
                    // Verify: Try to duplicate the handle and check if it points to our game
                    HANDLE hOwnerProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, handle.ProcessId);
                    if (hOwnerProcess != NULL) {
                        HANDLE hDuplicated = NULL;
                        
                        // Try to duplicate the handle
                        if (DuplicateHandle(
                            hOwnerProcess,
                            (HANDLE)(ULONG_PTR)handle.Handle,
                            GetCurrentProcess(),
                            &hDuplicated,
                            0,
                            FALSE,
                            DUPLICATE_SAME_ACCESS)) {

                            // Check if duplicated handle points to our game process
                            DWORD targetPid = GetProcessId(hDuplicated);
                            if (targetPid == gameProcessId) {
                                // CONFIRMED: This handle points to our game with dangerous access!
                                suspiciousProcess = processName + L" (PID:" + std::to_wstring(handle.ProcessId) + 
                                                   L", Access:0x" + std::to_wstring(handle.GrantedAccess) + L")";
#ifdef _DEBUG
                                std::wstring debugMsg = L"[AdvHeuristics] DETECTED SUSPICIOUS HANDLE to game: " + suspiciousProcess + L"\n";
                                OutputDebugStringW(debugMsg.c_str());
#endif
                                CloseHandle(hDuplicated);
                                CloseHandle(hOwnerProcess);
                                return true;
                            }
                            
                            CloseHandle(hDuplicated);
                        }
                        CloseHandle(hOwnerProcess);
                    }
                }
            }
        }

        return false;
    }

    bool AdvancedProcessHeuristics::HasSuspiciousPath(DWORD processId, std::wstring& matchedPath) const {
        // Buka handle ke process untuk query path
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
        if (hProcess == NULL) {
            return false;
        }

        wchar_t processPath[MAX_PATH * 2] = { 0 };
        DWORD pathSize = sizeof(processPath) / sizeof(processPath[0]);

        bool detected = false;

        // Get full executable path
        if (QueryFullProcessImageNameW(hProcess, 0, processPath, &pathSize)) {
            std::wstring fullPath(processPath);
            std::wstring lowerPath = ToLowerCopy(fullPath);

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
                    detected = true;
#ifdef _DEBUG
                    std::wstring debugMsg2 = L"[AdvHeuristics] DETECTED SUSPICIOUS PATH with keyword: " + keyword + L"\n";
                    OutputDebugStringW(debugMsg2.c_str());
#endif
                    break;
                }
            }
        }

        CloseHandle(hProcess);
        return detected;
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

    bool AdvancedProcessHeuristics::HasSuspiciousMemorySignature(DWORD processId, std::wstring& matchedPattern) const {
        // Buka handle ke process target dengan akses PROCESS_VM_READ dan PROCESS_QUERY_INFORMATION
        HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, processId);
        if (hProcess == NULL) {
            // Tidak bisa buka process - mungkin system process atau access denied
            return false;
        }

        bool detected = false;
        MEMORY_BASIC_INFORMATION mbi = { 0 };
        BYTE* address = nullptr;
        const size_t maxScanSize = 10 * 1024 * 1024; // Limit 10 MB per region untuk performa
        size_t totalScanned = 0;
        const size_t maxTotalScan = 100 * 1024 * 1024; // Max total 100 MB scan per process

        // Enumerate memory regions
        while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)) == sizeof(mbi)) {
            // Hanya scan region yang committed, readable, dan bukan guard page
            bool isExecutable = (mbi.Protect == PAGE_EXECUTE_READ || mbi.Protect == PAGE_EXECUTE_READWRITE);
            bool isReadable = (mbi.Protect == PAGE_READWRITE ||
                              mbi.Protect == PAGE_READONLY ||
                              isExecutable);
            
            if (mbi.State == MEM_COMMIT &&
                isReadable &&
                !(mbi.Protect & PAGE_GUARD) &&
                !(mbi.Protect & PAGE_NOACCESS)) {

                // Limit ukuran region yang di-scan
                size_t regionSize = mbi.RegionSize;
                if (regionSize > maxScanSize) {
                    regionSize = maxScanSize;
                }

                // Check total scan limit
                if (totalScanned + regionSize > maxTotalScan) {
                    break; // Stop scanning jika sudah terlalu banyak
                }

                // Allocate buffer untuk membaca memory
                std::vector<BYTE> buffer(regionSize);
                SIZE_T bytesRead = 0;

                if (ReadProcessMemory(hProcess, mbi.BaseAddress, buffer.data(), regionSize, &bytesRead) && bytesRead > 0) {
                    // Scan buffer untuk setiap signature
                    for (const auto& sig : kMemorySignatures) {
                        // Skip signature jika requires executable memory tapi region ini bukan executable
                        if (sig.requiresExecutableMemory && !isExecutable) {
                            continue;
                        }
                        
                        if (bytesRead < sig.patternSize) {
                            continue;
                        }

                        // Pattern matching dengan mask
                        for (size_t i = 0; i <= bytesRead - sig.patternSize; ++i) {
                            bool match = true;
                            for (size_t j = 0; j < sig.patternSize; ++j) {
                                if ((buffer[i + j] & sig.mask[j]) != (sig.pattern[j] & sig.mask[j])) {
                                    match = false;
                                    break;
                                }
                            }

                            if (match) {
                                matchedPattern = sig.name;
                                detected = true;
                                break;
                            }
                        }

                        if (detected) {
                            break;
                        }
                    }

                    totalScanned += bytesRead;
                }

                if (detected) {
                    break;
                }
            }

            // Move ke region berikutnya
            address = static_cast<BYTE*>(mbi.BaseAddress) + mbi.RegionSize;
        }

        CloseHandle(hProcess);
        return detected;
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

        int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, input.c_str(), -1, nullptr, 0, nullptr, nullptr);
        if (sizeNeeded <= 0) {
            return std::string();
        }

        std::string result(static_cast<size_t>(sizeNeeded) - 1, 0);
        WideCharToMultiByte(CP_UTF8, 0, input.c_str(), -1, &result[0], sizeNeeded, nullptr, nullptr);
        return result;
    }
}

