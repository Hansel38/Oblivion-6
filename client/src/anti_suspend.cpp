#include "pch.h"
#include "anti_suspend.h"
#include <windows.h>
#include <string>

// Forward declaration
extern void ReportViolationAndExit(const std::wstring& message, const std::string& type, const std::string& details);

namespace Oblivion {
    AntiSuspend::AntiSuspend() : m_isRunning(false) {
        // Inisialisasi heartbeat ke waktu saat ini
        m_lastHeartbeat.store(std::chrono::steady_clock::now());
    }

    AntiSuspend::~AntiSuspend() {
        Stop();
    }

    void AntiSuspend::Start() {
        if (m_isRunning) {
            return;
        }
        m_isRunning = true;
        m_guardianThread = std::thread(&AntiSuspend::GuardianLoop, this);
    }

    void AntiSuspend::Stop() {
        if (!m_isRunning) {
            return;
        }
        m_isRunning = false;
        if (m_guardianThread.joinable()) {
            m_guardianThread.join();
        }
    }

    void AntiSuspend::UpdateHeartbeat() {
        // Perbarui timestamp ke waktu saat ini
        m_lastHeartbeat.store(std::chrono::steady_clock::now());
    }

    void AntiSuspend::GuardianLoop() {
        // Timeout dalam milidetik. Harus lebih besar dari total waktu scan + interval tidur ProcessWatcher.
        // Signature verification bisa lambat (WinVerifyTrust, disk I/O), jadi timeout diperbesar.
        // Advanced heuristics + signature check bisa memakan 10-15 detik pada sistem lambat.
        const auto timeout = std::chrono::milliseconds(20000); // 20 detik (sebelumnya 8 detik)

        while (m_isRunning) {
            // Guardian tidur sebentar sebelum memeriksa
            Sleep(500);

            auto now = std::chrono::steady_clock::now();
            auto lastBeat = m_lastHeartbeat.load();

            // Hitung selisih waktu sejak heartbeat terakhir
            auto elapsed = now - lastBeat;

            if (elapsed > timeout) {
                // Heartbeat terlalu lama, ProcessWatcher kemungkinan di-suspend!
                // Hentikan Guardian untuk mencegah race condition
                m_isRunning = false;

                auto elapsedSeconds = std::chrono::duration_cast<std::chrono::seconds>(elapsed).count();
                std::string details = "Monitoring thread suspended or terminated - heartbeat timeout exceeded (" + 
                                     std::to_string(elapsedSeconds) + " seconds)";
                ReportViolationAndExit(L"", "THREAD_SUSPENDED", details);
            }
        }
    }
}