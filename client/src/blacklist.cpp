#include "pch.h"
#include "../include/blacklist.h"
#include <algorithm>
#include <cctype>

// Helper function for case-insensitive string comparison
static bool caseInsensitiveCompare(const std::wstring& a, const std::wstring& b) {
    if (a.length() != b.length()) {
        return false;
    }
    return std::equal(a.begin(), a.end(), b.begin(), [](wchar_t c1, wchar_t c2) {
        return towlower(c1) == towlower(c2);
        });
}

namespace Oblivion {
    bool IsProcessBlacklisted(const std::wstring& processName) {
        // Daftar nama proses yang dicurigai.
        // Bisa diperluas dengan membaca dari file atau server di kemudian hari.
        static const std::vector<std::wstring> blacklistedProcesses = {
            L"cheatengine.exe",
            L"cheat engine.exe",
            L"Cheat Engine",
            L"cheatengine-i386.exe",
            L"x64dbg.exe",
            L"ollydbg.exe",
            L"windbg.exe",
            L"ida.exe",
            L"ida64.exe",
            L"processhacker.exe",
            L"procmon.exe",
            L"wireshark.exe",
            L"wpe pro.exe",
            L"rpe.exe",
            L"openkore.exe",
            L"wexdist.exe",
            L"macro.exe",
            L"autohotkey.exe"
        };

        for (const auto& blacklistedName : blacklistedProcesses) {
            if (caseInsensitiveCompare(processName, blacklistedName)) {
                return true;
            }
        }

        return false;
    }
}