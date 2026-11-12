#pragma once

namespace Oblivion {
    class InjectionScanner {
    public:
        InjectionScanner();
        ~InjectionScanner();

        // Fungsi untuk memindai semua modul (DLL) yang dimuat
        void PerformScan();

    private:
        // Fungsi untuk memeriksa apakah nama DLL ada di daftar hitam
        bool IsDllBlacklisted(const wchar_t* dllName);
    };
}