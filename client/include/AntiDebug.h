#pragma once

#include <windows.h>
#include <string>

namespace Oblivion {
    class AntiDebug {
    public:
        AntiDebug();
        ~AntiDebug();

        // Fungsi utama untuk menjalankan semua pemeriksaan anti-debug
        void PerformCheck();

    private:
        // Metode 1: Menggunakan API IsDebuggerPresent
        bool CheckDebuggerPresentAPI();

        // Metode 2: Menggunakan NtQueryInformationProcess
        bool CheckNtQueryInfoProcess();

        // Metode 3: Jebakan dengan software exception (INT 3)
        bool CheckInt3Trap();

        // Metode 4: Deteksi hardware breakpoint via DR0–DR7
        bool CheckHardwareBreakpoints();

        // Metode 5: Deteksi kernel-mode debugger via SystemKernelDebuggerInformation
        bool CheckKernelDebugger();

        // Metode 6: Deteksi anomali timing akibat debugging/stepping
        bool CheckTimingAnomalies();

        // Metode 7: Validasi integritas fungsi kritis (anti-hook)
        bool CheckApiHookIntegrity();

        // Metode 8: Baca indikator debugger dari PEB
        bool CheckPEBFlags();

        // Metode 9: Integritas rantai SEH (x86) / heuristik x64
        bool CheckSEHChainIntegrity();

        // Metode 10: Integritas VEH (vectored exception handlers)
        bool CheckVEHIntegrity();
    };
}