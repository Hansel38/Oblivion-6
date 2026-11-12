#include "pch.h"
#include "overlay_scanner.h"
#include <vector>
#include <string>

// Forward declaration
extern void ReportViolationAndExit(const std::wstring& message, const std::string& type, const std::string& details);

namespace Oblivion {
    OverlayScanner::OverlayScanner() : m_gameWindow(NULL), m_gameRect{0, 0, 0, 0} {
        // Coba cari handle jendela game. "RagWindow" adalah class name default untuk Ragnarok.
        // Jika client Anda menggunakan class name berbeda, sesuaikan di sini.
        m_gameWindow = FindWindowW(L"RagWindow", NULL);
        if (m_gameWindow) {
            GetWindowRect(m_gameWindow, &m_gameRect);
        }
    }

    OverlayScanner::~OverlayScanner() {}

    void OverlayScanner::PerformScan() {
        // Jika jendela game belum ditemukan (misalnya saat DLL pertama kali dimuat),
        // coba cari lagi di setiap scan.
        if (!m_gameWindow) {
            m_gameWindow = FindWindowW(L"RagWindow", NULL);
            if (m_gameWindow) {
                GetWindowRect(m_gameWindow, &m_gameRect);
            }
        }

        // Jika masih tidak ditemukan, tidak ada yang bisa dipindai.
        if (!m_gameWindow) {
            return;
        }

        // Enumerasi semua jendela tingkat atas dan jalankan callback untuk masing-masing jendela
        EnumWindows(EnumWindowsCallback, (LPARAM)this);
    }

    BOOL CALLBACK OverlayScanner::EnumWindowsCallback(HWND hwnd, LPARAM lParam) {
        // Dapatkan instance OverlayScanner dari lParam
        OverlayScanner* pThis = reinterpret_cast<OverlayScanner*>(lParam);

        // Abaikan jendela kita sendiri
        if (hwnd == pThis->m_gameWindow) {
            return TRUE;
        }

        // 1. Periksa apakah jendela visible
        if (!IsWindowVisible(hwnd)) {
            return TRUE; // Lanjut ke jendela berikutnya
        }

        // 2. Periksa apakah jendela berpotongan dengan jendela game
        RECT overlayRect;
        GetWindowRect(hwnd, &overlayRect);
        RECT intersectionRect;
        if (!IntersectRect(&intersectionRect, &pThis->m_gameRect, &overlayRect)) {
            return TRUE; // Tidak berpotongan, lanjut
        }

        // 3. Periksa apakah jendela adalah topmost
        LONG_PTR exStyle = GetWindowLongPtr(hwnd, GWL_EXSTYLE);
        if (!(exStyle & WS_EX_TOPMOST)) {
            return TRUE; // Bukan topmost, lanjut
        }

        // 4. Periksa apakah jendela ada di whitelist
        wchar_t className[256];
        GetClassNameW(hwnd, className, 256);
        if (pThis->IsWhitelisted(className)) {
            return TRUE; // Ada di whitelist, aman. Lanjut.
        }

        // Jika sampai di sini, berarti semua kriteria terpenuhi:
        // - Visible
        // - Berpotongan dengan game
        // - Topmost
        // - Tidak ada di whitelist
        // Ini adalah overlay ilegal!

        // Konversi className ke UTF-8 untuk details
        std::string details_utf8;
        int size_needed = WideCharToMultiByte(CP_UTF8, 0, className, -1, NULL, 0, NULL, NULL);
        if (size_needed > 0) {
            details_utf8.assign(size_needed - 1, 0); // -1 untuk menghilangkan null terminator
            WideCharToMultiByte(CP_UTF8, 0, className, -1, &details_utf8[0], size_needed, NULL, NULL);
        }
        
        // Panggil fungsi pelaporan global
        ReportViolationAndExit(L"", "OVERLAY_DETECTED", details_utf8);

        // Kode tidak akan mencapai sini karena ExitProcess
        return FALSE;
    }

    bool OverlayScanner::IsWhitelisted(const wchar_t* className) {
        // Daftar class name dari overlay yang diizinkan.
        // PERHATIAN: Daftar ini sangat penting untuk mencegah false positive.
        // Tambahkan jika menemukan software sah yang diblokir.
        static const std::vector<std::wstring> whitelistedClasses = {
            L"Windows.UI.Core.CoreWindow", // UWP apps
            L"ApplicationFrameWindow", // UWP apps
            L"Shell_TrayWnd", // Taskbar
            L"DV2ControlHost", // Volume control
            L"ForegroundStaging", // Volume control
            L"Windows.UI.Input.InputSite.WindowClass", // Keyboard on-screen
            L"MSCTFIME UI", // IME
            L"IME", // IME
            L"tooltips_class32", // Tooltip
            L"SysShadow", // Shadow
            L"Button", // Standard button (rarely topmost)
            L"Static", // Static text
            L"Chrome_WidgetWin_1", // Chrome-based app notifications/overlays
            L"MozillaWindowClass", // Firefox-based overlays
            L"DiscordOverlay", // Discord Overlay
            L"SteamOverlay001", // Steam Overlay
            L"NotificationFlyout", // Windows 10/11 notifications
            L"ForegroundStaging", // Volume flyout
            L"OverlayClass" // Generic, but often used by benign tools. Use with caution.
        };

        for (const auto& whitelistedName : whitelistedClasses) {
            if (wcscmp(className, whitelistedName.c_str()) == 0) {
                return true;
            }
        }

        return false;
    }
}