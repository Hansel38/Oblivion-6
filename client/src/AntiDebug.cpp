#include "pch.h"
#include "AntiDebug.h"
#include <windows.h>
#include <winternl.h> // Untuk fungsi-fungsi NT yang tidak berdokumentasi

// Forward declaration
extern void ReportViolationAndExit(const std::wstring& message, const std::string& type, const std::string& details);

// Forward declare helper to silence missing identifier errors (definition appears later)
static bool IsModuleWhitelisted(HMODULE hMod);

// Fungsi pointer untuk NtQueryInformationProcess
typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(
    IN HANDLE ProcessHandle,
    IN PROCESSINFOCLASS ProcessInformationClass,
    OUT PVOID ProcessInformation,
    IN ULONG ProcessInformationLength,
    OUT PULONG ReturnLength OPTIONAL
    );

// VEH probe handler and flag (file-scope)
static volatile LONG gVehCalled = 0;
static LONG CALLBACK VehProbeHandler(PEXCEPTION_POINTERS p) {
    UNREFERENCED_PARAMETER(p);
    InterlockedExchange(&gVehCalled, 1);
    // Swallow exception to avoid crash during probe
    return EXCEPTION_CONTINUE_EXECUTION;
}

static bool IsAntiDebugDisabled() {
    wchar_t buf[8] = {0};
    DWORD n = GetEnvironmentVariableW(L"OBLIVION_ANTIDEBUG", buf, 8);
    if (n == 0 || n >= 8) return false;
    if (_wcsicmp(buf, L"0") == 0 || _wcsicmp(buf, L"false") == 0 || _wcsicmp(buf, L"off") == 0) return true;
    return false;
}

static bool IsStrictAntiDebug() {
    wchar_t buf[8] = {0};
    DWORD n = GetEnvironmentVariableW(L"OBLIVION_ANTIDEBUG_STRICT", buf, 8);
    if (n == 0 || n >= 8) return false;
    if (_wcsicmp(buf, L"1") == 0 || _wcsicmp(buf, L"true") == 0 || _wcsicmp(buf, L"on") == 0) return true;
    return false;
}

static bool ShouldLogAntiDebug() {
    wchar_t buf[8] = {0};
    DWORD n = GetEnvironmentVariableW(L"OBLIVION_ANTIDEBUG_LOG", buf, 8);
    if (n == 0 || n >= 8) return false;
    return (_wcsicmp(buf, L"1") == 0 || _wcsicmp(buf, L"true") == 0 || _wcsicmp(buf, L"on") == 0);
}

static void LogAntiDebugEvent(const std::string& details) {
    if (!ShouldLogAntiDebug()) return;

    wchar_t exePath[MAX_PATH] = {0};
    wchar_t logDir[MAX_PATH] = {0};
    DWORD dn = GetEnvironmentVariableW(L"OBLIVION_ANTIDEBUG_LOG_DIR", logDir, MAX_PATH);
    if (dn > 0 && dn < MAX_PATH) {
        // Ensure directory exists (best-effort)
        DWORD attrs = GetFileAttributesW(logDir);
        if (attrs == INVALID_FILE_ATTRIBUTES) {
            CreateDirectoryW(logDir, NULL);
        }
        // Build path: <logDir>\antidebug.log
        wcsncpy_s(exePath, logDir, _TRUNCATE);
        size_t len = wcslen(exePath);
        if (len > 0 && exePath[len - 1] != L'\\' && exePath[len - 1] != L'/') {
            wcscat_s(exePath, L"\\");
        }
        wcscat_s(exePath, L"antidebug.log");
    } else {
        if (!GetModuleFileNameW(NULL, exePath, MAX_PATH)) return;
        // Build log path next to the executable
        wchar_t* lastSlash = wcsrchr(exePath, L'\\');
        if (!lastSlash) return;
        *(lastSlash + 1) = L'\0';
        wcscat_s(exePath, L"antidebug.log");
    }

    HANDLE h = CreateFileW(exePath, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;

    // Move to end for append
    SetFilePointer(h, 0, NULL, FILE_END);

    SYSTEMTIME st; GetLocalTime(&st);
    char timeBuf[64];
    int len = sprintf_s(timeBuf, "%04d-%02d-%02d %02d:%02d:%02d ", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    DWORD written = 0;
    WriteFile(h, timeBuf, (DWORD)len, &written, NULL);
    WriteFile(h, details.c_str(), (DWORD)details.size(), &written, NULL);
    const char* nl = "\r\n";
    WriteFile(h, nl, 2, &written, NULL);

    CloseHandle(h);
}

namespace Oblivion {
    AntiDebug::AntiDebug() {}

    AntiDebug::~AntiDebug() {}

    void AntiDebug::PerformCheck() {
        if (IsAntiDebugDisabled()) {
            return;
        }

        bool strict = IsStrictAntiDebug();
        int hits = 0;
        std::string details;

        auto add = [&](const char* name, bool v) {
            if (v) {
                if (!details.empty()) details += ";";
                details += name;
                ++hits;
            }
            if (strict && v) {
                LogAntiDebugEvent(details);
                ReportViolationAndExit(L"", "DEBUGGER_DETECTED", details);
            }
        };

        add("IsDebuggerPresent", CheckDebuggerPresentAPI());
        add("NtQueryInfoProcess(DebugPort)", CheckNtQueryInfoProcess());
        add("INT3Trap", CheckInt3Trap());
        add("HWBreakpoints", CheckHardwareBreakpoints());
        add("KernelDebugger", CheckKernelDebugger());
        add("TimingAnomalies", CheckTimingAnomalies());
        add("ApiHookIntegrity", CheckApiHookIntegrity());
        add("PEBFlags", CheckPEBFlags());
        add("SEHChainIntegrity", CheckSEHChainIntegrity());
        add("VEHIntegrity", CheckVEHIntegrity());

        if (hits >= 2 && !details.empty()) {
            LogAntiDebugEvent(details);
            ReportViolationAndExit(L"", "DEBUGGER_DETECTED", details);
        }
    }

    bool AntiDebug::CheckDebuggerPresentAPI() {
        // Metode paling sederhana, mudah di-bypass tapi wajib ada.
        return IsDebuggerPresent() != FALSE;
    }

    bool AntiDebug::CheckNtQueryInfoProcess() {
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (!hNtdll) {
            return false; // Tidak bisa mendapatkan handle, asumsikan aman
        }

        pNtQueryInformationProcess NtQueryInfoProc = (pNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
        if (!NtQueryInfoProc) {
            return false; // Fungsi tidak ditemukan, asumsikan aman
        }

        DWORD processDebugPort = 0;
        NTSTATUS status = NtQueryInfoProc(
            GetCurrentProcess(),
            ProcessDebugPort, // Kelas informasi: 0x7
            &processDebugPort,
            sizeof(DWORD),
            NULL
        );

        // Jika status berhasil dan port debug bukan nol, debugger terdeteksi.
        if (status == 0x00000000 && processDebugPort != 0) {
            return true;
        }

        return false;
    }

    bool AntiDebug::CheckInt3Trap() {
        // Metode yang sangat kuat.
        // Kita mencoba menjalankan __debugbreak() yang memicu INT 3.
        // Jika debugger ada, ia akan menangkap exception.
        // Jika tidak, exception handler kita (dalam __except) yang akan menanganinya.
        __try {
            __debugbreak(); // Ini setara dengan int 3
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            // Kode di dalam blok ini hanya dijalankan jika TIDAK ADA debugger.
            // Jika kita sampai di sini, berarti aman.
            return false;
        }

        // Jika eksekusi berlanjut ke sini, berarti exception ditangkap oleh debugger,
        // bukan oleh handler kita.
        return true;
    }

    bool AntiDebug::CheckHardwareBreakpoints() {
        // Cek DR0–DR3 dan flag enable di DR7 pada thread saat ini
        CONTEXT ctx = {};
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (!GetThreadContext(GetCurrentThread(), &ctx)) {
            return false; // Tidak bisa mendapatkan konteks, asumsikan aman
        }

        bool anyDrSet = (ctx.Dr0 != 0) || (ctx.Dr1 != 0) || (ctx.Dr2 != 0) || (ctx.Dr3 != 0);
        bool dr7Enabled = (ctx.Dr7 & 0xFF) != 0; // Enable bits untuk local/global bp
        return anyDrSet || dr7Enabled;
    }

    bool AntiDebug::CheckKernelDebugger() {
        // Query SystemKernelDebuggerInformation untuk melihat apakah kernel debugger aktif
        typedef NTSTATUS (NTAPI* pNtQuerySystemInformation)(
            ULONG SystemInformationClass,
            PVOID SystemInformation,
            ULONG SystemInformationLength,
            PULONG ReturnLength
        );

        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (!hNtdll) return false;
        auto NtQuerySystemInformation = (pNtQuerySystemInformation)GetProcAddress(hNtdll, "NtQuerySystemInformation");
        if (!NtQuerySystemInformation) return false;

        struct KDI { // Struktur kecil untuk Kernel Debugger Info (bools)
            BOOLEAN KernelDebuggerEnabled;
            BOOLEAN KernelDebuggerNotPresent;
        } info = {0};

        // Nilai kelas 35 biasanya SystemKernelDebuggerInformation pada banyak build
        const ULONG SystemKernelDebuggerInformation = 35;
        NTSTATUS status = NtQuerySystemInformation(SystemKernelDebuggerInformation, &info, sizeof(info), nullptr);
        if (status != 0x00000000) {
            return false;
        }

        // Jika kernel debugger enabled dan tidak dianggap not present, anggap terdeteksi
        if (info.KernelDebuggerEnabled && !info.KernelDebuggerNotPresent) {
            return true;
        }
        return false;
    }

    bool AntiDebug::CheckTimingAnomalies() {
        // Baseline adaptif + beberapa sampling untuk mengurangi false positive
        LARGE_INTEGER f = {0};
        if (!QueryPerformanceFrequency(&f)) return false;

        auto sample = [&](int iters) -> double {
            LARGE_INTEGER s = {0}, e = {0};
            if (!QueryPerformanceCounter(&s)) return 0.0;
            for (volatile int i = 0; i < iters; ++i) {
            }
            if (!QueryPerformanceCounter(&e)) return 0.0;
            return (double)(e.QuadPart - s.QuadPart) * 1000.0 / (double)f.QuadPart;
        };

        static double baselineMs = 0.0;
        if (baselineMs <= 0.0) {
            // Hitung baseline dari beberapa sampel ringan
            const int iters = 100000;
            const int n = 3;
            double sum = 0.0;
            for (int i = 0; i < n; ++i) sum += sample(iters);
            baselineMs = sum / n;
            if (baselineMs <= 0.0) baselineMs = 10.0; // fallback konservatif
        }

        // Ambang adaptif: baseline * faktor + margin
        const double factor = 2.5; // debugger/stepping biasanya menggelembungkan waktu signifikan
        const double marginMs = 5.0;
        const double thresholdMs = baselineMs * factor + marginMs;

        // Lakukan beberapa sampel; jika mayoritas melewati ambang, anggap anomali
        int anomalies = 0;
        const int checks = 3;
        for (int i = 0; i < checks; ++i) {
            double t = sample(100000);
            if (t > thresholdMs) ++anomalies;
        }
        return anomalies >= 2; // konsensus sederhana
    }

    static bool IsAddressInModule(HMODULE mod, void* addr) {
        if (!mod || !addr) return false;
        auto dos = (PIMAGE_DOS_HEADER)mod;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
        auto nt = (PIMAGE_NT_HEADERS)((BYTE*)mod + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
        SIZE_T size = nt->OptionalHeader.SizeOfImage;
        return (addr >= (void*)mod) && ((BYTE*)addr < ((BYTE*)mod + size));
    }

    bool AntiDebug::CheckApiHookIntegrity() {
        // Validasi bahwa IsDebuggerPresent dan NtQueryInformationProcess menunjuk ke modul asli
        HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (!hKernel32 || !hNtdll) return false;

        FARPROC pIsDbg = GetProcAddress(hKernel32, "IsDebuggerPresent");
        FARPROC pNtQIP = GetProcAddress(hNtdll, "NtQueryInformationProcess");
        if (!pIsDbg || !pNtQIP) return false;

        // Jika alamat fungsi berada di luar modul aslinya, indikasi hooking (trampolin)
        bool isDbgHooked = !IsAddressInModule(hKernel32, (void*)pIsDbg);
        bool ntqipHooked = !IsAddressInModule(hNtdll, (void*)pNtQIP);

        // Tambahan: cek prolog untuk lompatan tidak biasa (heuristik sederhana)
        auto bytes = (BYTE*)pNtQIP;
        bool suspiciousJmp = (bytes[0] == 0xE9) || (bytes[0] == 0xEA) || (bytes[0] == 0xFF); // jmp/call absolute/indirect

        // Whitelist suppression
        if (isDbgHooked) {
            HMODULE actual = nullptr;
            if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                   (LPCWSTR)pIsDbg, &actual)) {
                if (actual && IsModuleWhitelisted(actual)) {
                    isDbgHooked = false;
                }
            }
        }
        if (ntqipHooked || suspiciousJmp) {
            HMODULE actual = nullptr;
            if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                   (LPCWSTR)pNtQIP, &actual)) {
                if (actual && IsModuleWhitelisted(actual)) {
                    ntqipHooked = false;
                    suspiciousJmp = false;
                }
            }
        }

        bool suspicious = isDbgHooked || ntqipHooked || suspiciousJmp;
        if (suspicious && ShouldLogAntiDebug()) {
            // Log detail modul asal alamat jika bukan modul asli
            auto logAddr = [&](const char* name, HMODULE expected, FARPROC addr) {
                HMODULE actual = nullptr;
                if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                       (LPCWSTR)addr, &actual)) {
                    wchar_t modName[MAX_PATH] = {0};
                    GetModuleFileNameW(actual, modName, MAX_PATH);
                    char utf8[512] = {0};
                    WideCharToMultiByte(CP_UTF8, 0, modName, -1, utf8, sizeof(utf8)-1, NULL, NULL);
                    char msg[768];
                    sprintf_s(msg, sizeof(msg), "APIHook %s addr=%p module=%s (expected=%p)", name, addr, utf8, expected);
                    LogAntiDebugEvent(std::string(msg));
                } else {
                    char msg[256];
                    sprintf_s(msg, sizeof(msg), "APIHook %s addr=%p (module unknown)", name, addr);
                    LogAntiDebugEvent(std::string(msg));
                }
            };

            if (isDbgHooked) logAddr("IsDebuggerPresent", hKernel32, pIsDbg);
            if (ntqipHooked || suspiciousJmp) logAddr("NtQueryInformationProcess", hNtdll, pNtQIP);
        }
        return suspicious;
    }

    bool AntiDebug::CheckPEBFlags() {
        // Baca BeingDebugged dan NtGlobalFlag dari PEB via NtQueryInformationProcess
        typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (!hNtdll) return false;
        auto NtQueryInfoProc = (pNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
        if (!NtQueryInfoProc) return false;

        // Ambil ProcessBasicInformation untuk mendapatkan PEB
        struct PROCESS_BASIC_INFORMATION_LOCAL {
            PVOID Reserved1;
            PVOID PebBaseAddress;
            PVOID Reserved2[2];
            ULONG UniqueProcessId;
            PVOID Reserved3;
        } pbi = {};

        NTSTATUS st = NtQueryInfoProc(GetCurrentProcess(), ProcessBasicInformation, &pbi, sizeof(pbi), nullptr);
        if (st != 0x00000000 || !pbi.PebBaseAddress) return false;

        // Struktur PEB minimal untuk membaca BeingDebugged dan NtGlobalFlag
        struct PEB_MIN {
            BYTE Reserved1[2];
            BYTE BeingDebugged;
            BYTE Reserved2[1];
            PVOID Reserved3[2];
            PVOID Ldr;
            PVOID ProcessParameters;
            BYTE Reserved4[104];
            ULONG NtGlobalFlag;
        };

        auto peb = (PEB_MIN*)pbi.PebBaseAddress;
        __try {
            bool dbg = peb->BeingDebugged != 0;
            // NtGlobalFlag sering memiliki 0x70 jika di bawah debugger (FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK)
            bool ngf = (peb->NtGlobalFlag & 0x70) != 0;
            return dbg || ngf;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
    }

    bool AntiDebug::CheckSEHChainIntegrity() {
        // Catatan: Pada x86, rantai SEH berada di FS:[0]. Pada x64, SEH tidak menggunakan linked list yang sama.
        // Implementasi: x86 → validasi panjang rantai dan modul handler; x64 → heuristik lemah (return false).
#if defined(_M_IX86)
        struct EXCEPTION_REGISTRATION_RECORD {
            EXCEPTION_REGISTRATION_RECORD* Next;
            PVOID Handler;
        };

        EXCEPTION_REGISTRATION_RECORD* p = nullptr;
        __asm {
            mov eax, dword ptr fs:[0]
            mov p, eax
        }

        int depth = 0;
        const int maxDepth = 64; // kedalaman wajar; terlalu dalam bisa indikasi hooking aneh
        while (p && p != (EXCEPTION_REGISTRATION_RECORD*)0xFFFFFFFF && depth < maxDepth) {
            // Validasi handler berada dalam modul proses (ntdll/kernel32/our module)
            HMODULE hMod = nullptr;
            if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                   (LPCSTR)p->Handler, &hMod)) {
                // Jika handler berada di modul yang tidak dikenal, anggap mencurigakan
                wchar_t modName[MAX_PATH] = {0};
                GetModuleFileNameW(hMod, modName, MAX_PATH);
                bool allowed = (wcsstr(modName, L"ntdll.dll") != nullptr) ||
                               (wcsstr(modName, L"kernel32.dll") != nullptr);
                HMODULE hSelf = nullptr;
                if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                       (LPCWSTR)&IsAddressInModule, &hSelf)) {
                    if (hSelf && hMod == hSelf) {
                        allowed = true;
                    }
                }
                // Cek modul kita (client dll) jika diketahui nama
                // Jika tidak termasuk yang diizinkan, flag
                if (!allowed) {
                    if (ShouldLogAntiDebug()) {
                        std::string msg = "SEH suspicious module: ";
                        char utf8[512] = {0};
                        WideCharToMultiByte(CP_UTF8, 0, modName, -1, utf8, sizeof(utf8)-1, NULL, NULL);
                        msg += utf8;
                        LogAntiDebugEvent(msg);
                    }
                    return true; // integritas SEH mencurigakan
                }
            }

            p = p->Next;
            ++depth;
        }

        if (depth >= maxDepth) {
            if (ShouldLogAntiDebug()) LogAntiDebugEvent("SEH chain too deep");
            return true; // rantai terlalu dalam → indikasi manipulasi
        }
        return false;
#else
        // Pada x64, tidak ada linked-list SEH tradisional; skip dengan aman
        return false;
#endif
    }

    bool AntiDebug::CheckVEHIntegrity() {
        // Pasang VEH sementara, picu exception, dan verifikasi handler kita dipanggil.
        // Jika tidak, kemungkinan ada VEH lain yang menelan exception secara tidak wajar.
        // Reset flag sebelum test
        InterlockedExchange(&gVehCalled, 0);

        // Tahap 1: pasang dengan prioritas lebih rendah (1) agar handler lain yang lebih tinggi bisa jalan
        PVOID hVeh = AddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)VehProbeHandler);
        if (!hVeh) {
            return false;
        }
        RaiseException(0xE0424242, 0, 0, nullptr); // benign custom exception; swallowed by our handler if reached

        RemoveVectoredExceptionHandler(hVeh);

        if (InterlockedCompareExchange(&gVehCalled, 0, 0) == 0) {
            // Tahap 2: retry dengan prioritas tertinggi (0).
            // Jika pada prioritas 0 handler kita dipanggil, anggap benign (whitelist kemungkinan handler dari modul sendiri).
            InterlockedExchange(&gVehCalled, 0);
            PVOID hVeh2 = AddVectoredExceptionHandler(0, (PVECTORED_EXCEPTION_HANDLER)VehProbeHandler);
            if (!hVeh2) return false;
            RaiseException(0xE0424242, 0, 0, nullptr);
            RemoveVectoredExceptionHandler(hVeh2);
            // Jika tetap tidak dipanggil pada prioritas tertinggi, flag mencurigakan
            bool suspicious = (InterlockedCompareExchange(&gVehCalled, 0, 0) == 0);
            if (suspicious && ShouldLogAntiDebug()) LogAntiDebugEvent("VEH suspicious: handler swallowed exceptions at all priorities");
            return suspicious;
        }

        // Dipanggil pada prioritas 1 → integritas oke
        return false;
    }
}
static bool IsModuleWhitelisted(HMODULE hMod) {
    wchar_t wl[1024] = {0};
    DWORD n = GetEnvironmentVariableW(L"OBLIVION_HOOK_WHITELIST", wl, 1024);
    if (n == 0 || n >= 1024) return false;

    wchar_t modPath[MAX_PATH] = {0};
    if (!GetModuleFileNameW(hMod, modPath, MAX_PATH)) return false;
    wchar_t* fname = wcsrchr(modPath, L'\\');
    fname = fname ? (fname + 1) : modPath;

    wchar_t fnameLower[MAX_PATH] = {0};
    wcsncpy_s(fnameLower, fname, _TRUNCATE);
    _wcslwr_s(fnameLower, wcslen(fnameLower) + 1);

    wchar_t* ctx = nullptr;
    wchar_t* token = wcstok_s(wl, L";", &ctx);
    while (token) {
        while (*token == L' ' || *token == L'\t') ++token;
        size_t len = wcslen(token);
        while (len && (token[len-1] == L' ' || token[len-1] == L'\t')) { token[--len] = L'\0'; }
        _wcslwr_s(token, len + 1);
        if (len && wcsstr(fnameLower, token) != nullptr) {
            return true;
        }
        token = wcstok_s(nullptr, L";", &ctx);
    }
    return false;
}