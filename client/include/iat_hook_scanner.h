#pragma once

#include <windows.h>

namespace Oblivion {
    class IATHookScanner {
    public:
        IATHookScanner();
        ~IATHookScanner();

        // Fungsi utama untuk memindai IAT
        void PerformScan();

    private:
        // Tidak ada fungsi private yang diperlukan untuk kesederhanaan
    };
}