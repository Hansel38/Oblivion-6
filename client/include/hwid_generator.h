#pragma once

#include <string>

namespace Oblivion {
    class HWIDGenerator {
    public:
        // Fungsi statis untuk memudahkan pemanggilan
        static std::string Generate();

    private:
        // Fungsi helper untuk mendapatkan informasi CPU
        static std::string GetCpuBrand();

        // Fungsi helper untuk mendapatkan properti dari WMI
        static std::string GetWmiProperty(const std::string& wmiClass, const std::string& wmiProperty);

        // Fungsi helper untuk meng-hash string (re-use dari File Integrity Check)
        static std::string HashString(const std::string& input);
    };
}