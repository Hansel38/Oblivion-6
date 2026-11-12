#include "pch.h"
#include "overlay_scanner.h"
#include <vector>
#include <string>

// Forward declaration
extern void ReportViolationAndExit(const std::wstring& message, const std::string& type, const std::string& details);

namespace {
    std::string WideToUtf8(const wchar_t* value) {
        if (!value) return {};
        const int required = WideCharToMultiByte(CP_UTF8, 0, value, -1, nullptr, 0, nullptr, nullptr);
        if (required <= 0) return {};

        // Allocate the terminator too; remove it only after conversion succeeds.
        std::string converted(static_cast<size_t>(required), '\0');
        const int written = WideCharToMultiByte(CP_UTF8, 0, value, -1,
                                                &converted[0], required, nullptr, nullptr);
        if (written != required) return {};
        converted.pop_back();
        return converted;
    }
}

namespace Oblivion {
    OverlayScanner::OverlayScanner() : m_gameWindow(NULL), m_gameRect{0, 0, 0, 0} {
        // Coba cari handle jendela game. "RagWindow" adalah class name default untuk Ragnarok.
        // Jika client Anda menggunakan class name berbeda, sesuaikan di sini.
        m_gameWindow = FindWindowW(L"RagWindow", NULL);
        if (m_gameWindow && !GetWindowRect(m_gameWindow, &m_gameRect)) {
            m_gameWindow = NULL;
        }
    }

    OverlayScanner::~OverlayScanner() {}

    void OverlayScanner::PerformScan() {
        // Jika jendela game belum ditemukan (misalnya saat DLL pertama kali dimuat),
        // coba cari lagi di setiap scan.
        if (m_gameWindow && !IsWindow(m_gameWindow)) {
            m_gameWindow = NULL;
        }
        if (!m_gameWindow) {
            m_gameWindow = FindWindowW(L"RagWindow", NULL);
        }
        if (!m_gameWindow || !GetWindowRect(m_gameWindow, &m_gameRect)) {
            m_gameWindow = NULL;
            return;
        }

        // Refresh the game rectangle on every pass (window movement/resizing).
        // Enumerasi semua jendela tingkat atas dan jalankan callback untuk masing-masing jendela
        EnumWindows(EnumWindowsCallback, (LPARAM)this);
    }

    BOOL CALLBACK OverlayScanner::EnumWindowsCallback(HWND hwnd, LPARAM lParam) {
        // Dapatkan instance OverlayScanner dari lParam
        OverlayScanner* pThis = reinterpret_cast<OverlayScanner*>(lParam);
        if (!pThis || !IsWindow(hwnd)) return TRUE;

        // Abaikan jendela kita sendiri
        if (hwnd == pThis->m_gameWindow) {
            return TRUE;
        }

        // 1. Periksa apakah jendela visible
        if (!IsWindowVisible(hwnd)) {
            return TRUE; // Lanjut ke jendela berikutnya
        }

        // 2. Periksa apakah jendela berpotongan dengan jendela game
        RECT overlayRect{};
        if (!GetWindowRect(hwnd, &overlayRect)) return TRUE;
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
        wchar_t className[256] = {};
        if (GetClassNameW(hwnd, className, 256) == 0) {
            return TRUE;
        }
        if (pThis->IsWhitelisted(className)) {
            return TRUE; // Ada di whitelist, aman. Lanjut.
        }

        // Jika sampai di sini, berarti semua kriteria terpenuhi:
        // - Visible
        // - Berpotongan dengan game
        // - Topmost
        // - Tidak ada di whitelist
        // Ini adalah overlay ilegal!

        const std::string details_utf8 = WideToUtf8(className);
        
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