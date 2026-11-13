#include "pch.h"
#include "process_watcher.h"
#include "file_integrity_check.h"
#include "network_reporter.h"
#include "self_integrity_guard.h"
#include "secret_obf.h"
#include <windows.h>
#include <thread>
#include <mutex>
#include <atomic>
#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <objidl.h>
#include <gdiplus.h>
#pragma comment(lib, "gdiplus.lib")

// Global instance dari ProcessWatcher
static Oblivion::ProcessWatcher* g_pProcessWatcher = nullptr;

// Buat instance global NetworkReporter agar bisa diakses
// Ganti 127.0.0.1 dengan IP server Anda
static Oblivion::NetworkReporter* g_pNetworkReporter = nullptr;
static Oblivion::SelfIntegrityGuard* g_pSelfIntegrityGuard = nullptr;
static HMODULE g_hSelfModule = nullptr;

namespace {
    enum class LifecycleState {
        NotStarted,
        Starting,
        Started,
        Stopping,
        Stopped
    };

    struct LifecycleControl {
        std::mutex mutex;
        std::thread initializationThread;
        std::atomic<bool> shutdownRequested{ false };
        LifecycleState state = LifecycleState::NotStarted;
    };

    LifecycleControl& GetLifecycleControl() {
        static LifecycleControl control;
        return control;
    }
}

void InitializeSecuritySystem();

// The injector/host must call this export after LoadLibrary succeeds.
// Initialization is deliberately started outside DllMain and therefore outside
// the Windows loader lock.
extern "C" __declspec(dllexport) void Oblivion_Entry() {
    LifecycleControl& lifecycle = GetLifecycleControl();
    std::lock_guard<std::mutex> lock(lifecycle.mutex);

    if (lifecycle.state != LifecycleState::NotStarted) {
        return;
    }

    lifecycle.state = LifecycleState::Starting;
    lifecycle.shutdownRequested.store(false);

    try {
        lifecycle.initializationThread = std::thread([]() {
            try {
                InitializeSecuritySystem();
            } catch (...) {
                OutputDebugStringW(L"[ERROR] Unhandled exception during Oblivion initialization.");
            }

            LifecycleControl& state = GetLifecycleControl();
            std::lock_guard<std::mutex> stateLock(state.mutex);
            if (state.state == LifecycleState::Starting) {
                state.state = LifecycleState::Started;
            }
        });
    } catch (...) {
        lifecycle.state = LifecycleState::Stopped;
        OutputDebugStringW(L"[ERROR] Failed to create Oblivion initialization thread.");
    }
}

// The host must call this export before FreeLibrary. It runs outside DllMain,
// requests cancellation, joins initialization, then stops workers in dependency
// order so no worker can use NetworkReporter after it is destroyed.
extern "C" __declspec(dllexport) void Oblivion_Shutdown() {
    LifecycleControl& lifecycle = GetLifecycleControl();
    std::thread initializationThread;

    {
        std::lock_guard<std::mutex> lock(lifecycle.mutex);
        if (lifecycle.state == LifecycleState::Stopped) {
            return;
        }

        lifecycle.shutdownRequested.store(true);
        lifecycle.state = LifecycleState::Stopping;

        if (lifecycle.initializationThread.joinable()) {
            // Shutdown is a host-thread API. If misused from the initialization
            // thread, leave the joinable thread for a later host-thread call.
            if (lifecycle.initializationThread.get_id() == std::this_thread::get_id()) {
                return;
            }
            initializationThread = std::move(lifecycle.initializationThread);
        }
    }

    if (initializationThread.joinable()) {
        initializationThread.join();
    }

    if (g_pProcessWatcher) {
        try {
            g_pProcessWatcher->Stop();
        } catch (...) {
        }
        delete g_pProcessWatcher;
        g_pProcessWatcher = nullptr;
    }

    if (g_pSelfIntegrityGuard) {
        try {
            g_pSelfIntegrityGuard->Stop();
        } catch (...) {
        }
        delete g_pSelfIntegrityGuard;
        g_pSelfIntegrityGuard = nullptr;
    }

    if (g_pNetworkReporter) {
        delete g_pNetworkReporter;
        g_pNetworkReporter = nullptr;
    }

    {
        std::lock_guard<std::mutex> lock(lifecycle.mutex);
        lifecycle.state = LifecycleState::Stopped;
    }
}

// Fungsi helper untuk melaporkan pelanggaran
void ReportViolationAndExit(const std::wstring& message, const std::string& type, const std::string& details) {
    LifecycleControl& lifecycle = GetLifecycleControl();
    if (lifecycle.shutdownRequested.load()) {
        return;
    }

    // Tunggu maksimal 5 detik untuk NetworkReporter siap (jika belum siap),
    // tetapi jangan menahan worker bila host sedang menghentikan DLL.
    int waitCount = 0;
    while (!g_pNetworkReporter && waitCount < 50 &&
           !lifecycle.shutdownRequested.load()) {
        Sleep(100);
        waitCount++;
    }

    if (lifecycle.shutdownRequested.load()) {
        return;
    }
    
    // Kirim laporan ke server (BLOCKING - menunggu respons)
    // ReportViolation akan menunggu respons dari server dan menampilkan message box
    // Jika server mengirim KICK, ReportViolation akan memanggil ExitProcess
    if (g_pNetworkReporter) {
        g_pNetworkReporter->ReportViolation(type, details);
        // Jika sampai di sini, berarti server tidak mengirim KICK atau timeout
        // Tampilkan pesan default dan tutup client
        if (!message.empty()) {
            MessageBoxW(NULL, message.c_str(), L"Oblivion Hack Shield - Violation", MB_OK | MB_ICONERROR | MB_TOPMOST);
        }
        ExitProcess(0);
    } else {
        // Jika reporter belum siap setelah timeout, fallback ke penutupan lokal
        if (!message.empty()) {
            MessageBoxW(NULL, message.c_str(), L"Oblivion Hack Shield - Violation", MB_OK | MB_ICONERROR | MB_TOPMOST);
        }
        ExitProcess(0);
    }
}

// buat disable atau enable debug console
bool ShouldHideDebugConsole() {
    constexpr int kConsoleToggle = 1; // 0 = console tampil, 1 = console tersembunyi
    return kConsoleToggle == 1;
}

// Fungsi inisialisasi yang dijalankan di thread terpisah
void InitializeSecuritySystem() {
    // Tampilkan Splash Screen (non-blocking terhadap loader, tapi menjalankan loop singkat)
    auto ShowSplash = []() {
        using namespace Gdiplus;
        ULONG_PTR gdiplusToken = 0;
        GdiplusStartupInput gdiplusStartupInput;
        if (GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, nullptr) != Ok) {
            return; // Jika GDI+ gagal, lanjut tanpa splash
        }

        const HMODULE module = g_hSelfModule ? g_hSelfModule : GetModuleHandleW(nullptr);
        constexpr size_t kInitialPathCapacity = MAX_PATH;
        constexpr size_t kMaximumPathCapacity = 32768;
        std::vector<wchar_t> modulePath(kInitialPathCapacity);
        DWORD modulePathLength = 0;

        while (modulePath.size() <= kMaximumPathCapacity) {
            const DWORD capacity = static_cast<DWORD>(modulePath.size());
            const DWORD length = GetModuleFileNameW(module, modulePath.data(), capacity);
            if (length == 0) {
                break;
            }
            if (length < capacity) {
                modulePathLength = length;
                break;
            }
            if (modulePath.size() == kMaximumPathCapacity) {
                break;
            }
            modulePath.resize((std::min)(modulePath.size() * 2, kMaximumPathCapacity));
        }

        if (modulePathLength == 0) {
            GdiplusShutdown(gdiplusToken);
            return;
        }

        std::wstring modulePathString(modulePath.data(), modulePathLength);
        const size_t lastSlash = modulePathString.find_last_of(L"\\/");
        if (lastSlash == std::wstring::npos) {
            GdiplusShutdown(gdiplusToken);
            return;
        }
        modulePathString.resize(lastSlash);
        const std::wstring imagePath = modulePathString + L"\\logo\\OblivionHS.png";

        HWND hwndSplash = nullptr;
        HBITMAP hBmp = nullptr;
        Bitmap *img = nullptr;
        img = Bitmap::FromFile(imagePath.c_str(), FALSE);
        if (!img || img->GetLastStatus() != Ok) {
            delete img;
            GdiplusShutdown(gdiplusToken);
            return; // Tidak ada gambar, abaikan
        }

        const int imgW = static_cast<int>(img->GetWidth());
        const int imgH = static_cast<int>(img->GetHeight());

        WNDCLASSW wc{};
        wc.lpfnWndProc = [](HWND h, UINT m, WPARAM w, LPARAM l)->LRESULT {
            if (m == WM_PAINT) {
                PAINTSTRUCT ps; HDC hdc = BeginPaint(h, &ps);
                RECT rc; GetClientRect(h, &rc);
                Graphics g(hdc);
                g.SetInterpolationMode(InterpolationModeHighQualityBicubic);
                g.SetPixelOffsetMode(PixelOffsetModeHighQuality);
                g.SetSmoothingMode(SmoothingModeHighQuality);
                // Tarik pointer image dari properti window
                Bitmap* pImg = reinterpret_cast<Bitmap*>(GetPropW(h, L"__OBV_IMG"));
                if (pImg) {
                    // Render image dengan ukuran penuh sesuai client area
                    g.DrawImage(pImg, 0, 0, rc.right, rc.bottom);
                }
                EndPaint(h, &ps);
                return 0;
            }
            return DefWindowProcW(h, m, w, l);
        };
        wc.hInstance = GetModuleHandleW(nullptr);
        wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
        wc.lpszClassName = L"OblivionSplashClass";
        RegisterClassW(&wc);

        // Hitung ukuran window dengan border adjustment untuk WS_POPUP
        RECT rect = {0, 0, imgW, imgH};
        AdjustWindowRectEx(&rect, WS_POPUP, FALSE, WS_EX_TOPMOST | WS_EX_TOOLWINDOW);
        int windowW = rect.right - rect.left;
        int windowH = rect.bottom - rect.top;

        // Posisi center layar
        int screenW = GetSystemMetrics(SM_CXSCREEN);
        int screenH = GetSystemMetrics(SM_CYSCREEN);
        int x = (screenW - windowW) / 2;
        int y = (screenH - windowH) / 2;

        hwndSplash = CreateWindowExW(
            WS_EX_TOPMOST | WS_EX_TOOLWINDOW,
            wc.lpszClassName,
            L"Oblivion Hack Shield",
            WS_POPUP,
            x, y, windowW, windowH,
            nullptr, nullptr, wc.hInstance, nullptr);

        if (!hwndSplash) {
            delete img;
            GdiplusShutdown(gdiplusToken);
            return;
        }

        SetPropW(hwndSplash, L"__OBV_IMG", reinterpret_cast<HANDLE>(img));
        ShowWindow(hwndSplash, SW_SHOW);
        UpdateWindow(hwndSplash);

        // Jalankan message loop singkat selama 2000 ms
        const ULONGLONG durationMs = 2000;
        ULONGLONG start = GetTickCount64();
        MSG msg;
        while (GetTickCount64() - start < durationMs &&
               !GetLifecycleControl().shutdownRequested.load()) {
            while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
            Sleep(10);
        }

        RemovePropW(hwndSplash, L"__OBV_IMG");
        DestroyWindow(hwndSplash);
        delete img;
        GdiplusShutdown(gdiplusToken);
    };

    // Tampilkan splash sebelum console init. The loop is cancellable by shutdown.
    ShowSplash();
    if (GetLifecycleControl().shutdownRequested.load()) return;

    // --- LANGKAH PERTAMA: BUAT CONSOLE UNTUK DEBUGGING ---
    const bool hideConsole = ShouldHideDebugConsole();
    if (!hideConsole) {
        // Sesuai requirement: client menggunakan Console
        AllocConsole();
        FILE* fDummy;
        freopen_s(&fDummy, "CONOUT$", "w", stdout);
        freopen_s(&fDummy, "CONOUT$", "w", stderr);
        freopen_s(&fDummy, "CONIN$", "r", stdin);
        std::cout.clear();
        std::clog.clear();
        std::cerr.clear();
        std::cin.clear();

        SetConsoleTitleW(L"Oblivion Hack Shield - Debug Console");
        std::cout << "==================================================" << std::endl;
        std::cout << "  OBLIVION HACK SHIELD - Anti-Cheat System" << std::endl;
        std::cout << "  Version 1.0 - Ragnarok Online Protection" << std::endl;
        std::cout << "==================================================" << std::endl;
        std::cout << "[INIT] Console initialized" << std::endl;
    } else {
        OutputDebugStringW(L"[INFO] Oblivion Hack Shield debug console disabled via configuration.");
    }
    
    if (GetLifecycleControl().shutdownRequested.load()) return;

    // --- LANGKAH KEDUA: BUAT NETWORK REPORTER ---
    std::cout << "[INIT] Creating network reporter..." << std::endl;
    try {
        // Ambil secret yang di-obfuscate (bukan string literal langsung)
        const std::string kClientSecret = Oblivion::GetClientSecret();
        // TODO: Ganti "127.0.0.1" dengan IP VPS server Anda
        // Contoh: "192.168.1.100" atau "your-server-ip.com"
        g_pNetworkReporter = new Oblivion::NetworkReporter("127.0.0.1", 54321, kClientSecret);
        std::cout << "[INIT] Network reporter created" << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "[ERROR] Failed to create network reporter: " << e.what() << std::endl;
        MessageBoxW(NULL, L"Gagal menginisialisasi network reporter.\n\nClient akan ditutup.", 
                    L"Oblivion Hack Shield - Error", MB_OK | MB_ICONERROR | MB_TOPMOST);
        ExitProcess(1);
    } catch (...) {
        std::cerr << "[ERROR] Unknown error creating network reporter" << std::endl;
        MessageBoxW(NULL, L"Kesalahan tidak diketahui saat inisialisasi.\n\nClient akan ditutup.", 
                    L"Oblivion Hack Shield - Error", MB_OK | MB_ICONERROR | MB_TOPMOST);
        ExitProcess(1);
    }

    if (GetLifecycleControl().shutdownRequested.load()) return;

    // --- LANGKAH KETIGA: CEK BAN STATUS DARI SERVER ---
    std::cout << "[INIT] Checking ban status with server..." << std::endl;
    try {
        if (!g_pNetworkReporter->CheckBanStatus()) {
            // Jika di-ban, CheckBanStatus sudah memanggil ExitProcess, jadi tidak akan sampai di sini
            return;
        }
        std::cout << "[INIT] Ban check passed" << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "[ERROR] Exception during ban check: " << e.what() << std::endl;
        MessageBoxW(NULL, L"Kesalahan saat memeriksa status ban.\n\nClient akan ditutup.", 
                    L"Oblivion Hack Shield - Error", MB_OK | MB_ICONERROR | MB_TOPMOST);
        ExitProcess(1);
    }

    if (GetLifecycleControl().shutdownRequested.load()) return;

    // --- LANGKAH KEEMPAT: PERIKSA INTEGRITAS FILE ---
    std::cout << "[INIT] Performing file integrity check..." << std::endl;
    try {
        Oblivion::FileIntegrityChecker integrityChecker;
        integrityChecker.PerformCheck();
        std::cout << "[INIT] File integrity check passed" << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "[ERROR] File integrity check failed: " << e.what() << std::endl;
        ReportViolationAndExit(L"", "FILE_INTEGRITY_EXCEPTION", e.what());
        return;
    } catch (...) {
        std::cerr << "[ERROR] Unknown error during file integrity check" << std::endl;
        ReportViolationAndExit(L"", "FILE_INTEGRITY_UNKNOWN_ERROR", "Unknown exception");
        return;
    }

    if (GetLifecycleControl().shutdownRequested.load()) return;

    // --- LANGKAH KELIMA: AKTIFKAN SELF-INTEGRITY GUARD ---
    std::cout << "[INIT] Starting self-integrity guard..." << std::endl;
    try {
        if (!g_pSelfIntegrityGuard) {
            g_pSelfIntegrityGuard = new Oblivion::SelfIntegrityGuard(g_hSelfModule);
            if (!g_pSelfIntegrityGuard->Start()) {
                std::cerr << "[ERROR] Self-integrity guard failed to start" << std::endl;
                ReportViolationAndExit(L"", "SELF_GUARD_INIT_FAILED", "Unable to initialize self integrity guard");
                return;
            }
            std::cout << "[INIT] Self-integrity guard active" << std::endl;
        }
    } catch (const std::exception& e) {
        std::cerr << "[ERROR] Exception starting self-integrity guard: " << e.what() << std::endl;
        ReportViolationAndExit(L"", "SELF_GUARD_EXCEPTION", e.what());
        return;
    }

    if (GetLifecycleControl().shutdownRequested.load()) return;

    // --- LANGKAH KEENAM: MULAI SISTEM PEMANTAUAN ---
    std::cout << "[INIT] Starting process watcher..." << std::endl;
    try {
        g_pProcessWatcher = new Oblivion::ProcessWatcher();
        g_pProcessWatcher->Start();
        std::cout << "[SUCCESS] Oblivion Hack Shield fully initialized!" << std::endl;
        std::cout << "[INFO] Protection active - monitoring for threats..." << std::endl;
        std::cout << "==================================================" << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "[ERROR] Exception starting process watcher: " << e.what() << std::endl;
        ReportViolationAndExit(L"", "PROCESS_WATCHER_EXCEPTION", e.what());
        return;
    }
}

// DLL entry point: keep it minimal. No thread creation, joins, logging, deletes,
// or other blocking cleanup are allowed while the loader lock is held.
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    (void)lpReserved;

    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        g_hSelfModule = hModule;
    }

    // On explicit unload, the host must call Oblivion_Shutdown() first.
    // Process termination is handled by the operating system.
    return TRUE;
}