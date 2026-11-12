#pragma once

#include <chrono>
#include <atomic>
#include <thread>

namespace Oblivion {
    class AntiSuspend {
    public:
        AntiSuspend();
        ~AntiSuspend();

        // Memulai Guardian Thread
        void Start();

        // Menghentikan Guardian Thread secara aman
        void Stop();

        // Fungsi ini akan dipanggil oleh ProcessWatcher untuk memberi sinyal bahwa ia masih hidup
        void UpdateHeartbeat();

    private:
        // Fungsi utama yang dijalankan oleh Guardian Thread
        void GuardianLoop();

        std::thread m_guardianThread;
        std::atomic<bool> m_isRunning;

        // Timestamp dari heartbeat terakhir. Menggunakan steady_clock untuk pengukuran waktu yang akurat.
        std::atomic<std::chrono::steady_clock::time_point> m_lastHeartbeat;
    };
}