#pragma once

#include <windows.h>

namespace Oblivion {
    class OverlayScanner {
    public:
        OverlayScanner();
        ~OverlayScanner();

        // Fungsi utama untuk memindai overlay
        void PerformScan();

    private:
        // Fungsi callback statis yang akan dipanggil oleh EnumWindows
        static BOOL CALLBACK EnumWindowsCallback(HWND hwnd, LPARAM lParam);

        // Fungsi untuk memeriksa apakah window class ada di whitelist
        bool IsWhitelisted(const wchar_t* className);

        // Handle dan rectangle dari jendela game
        HWND m_gameWindow;
        RECT m_gameRect;
    };
}