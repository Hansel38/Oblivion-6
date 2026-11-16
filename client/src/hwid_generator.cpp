#include "pch.h"
#include "hwid_generator.h"
#include <intrin.h> // Untuk __cpuid
#include <vector>
#include <sstream>
#include <iomanip>
#include <bcrypt.h> // Untuk hashing
#include <comdef.h> // Untuk _bstr_t
#include <Wbemidl.h>
#include <memory>

// Definisi NTSTATUS jika ntstatus.h tidak tersedia
#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#endif

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "wbemuuid.lib") // Untuk WMI
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

namespace {
    class ScopedComInitialization final {
    public:
        explicit ScopedComInitialization(DWORD coInit) noexcept
            : result_(CoInitializeEx(nullptr, coInit)),
              initialized_(result_ == S_OK || result_ == S_FALSE) {
        }

        ~ScopedComInitialization() {
            if (initialized_) {
                CoUninitialize();
            }
        }

        ScopedComInitialization(const ScopedComInitialization&) = delete;
        ScopedComInitialization& operator=(const ScopedComInitialization&) = delete;

        bool IsInitialized() const noexcept {
            return initialized_;
        }

    private:
        HRESULT result_;
        bool initialized_;
    };
    template <typename T>
    struct ComRelease final {
        void operator()(T* value) const noexcept {
            if (value != nullptr) value->Release();
        }
    };
}

namespace Oblivion {
    std::string HWIDGenerator::Generate() {
        std::string cpuBrand = GetCpuBrand();
        std::string motherboardUuid = GetWmiProperty("Win32_BaseBoard", "UUID");
        std::string hddSerial = GetWmiProperty("Win32_DiskDrive", "SerialNumber");

        // Ambil hanya drive pertama untuk kesederhanaan
        if (hddSerial.find(",") != std::string::npos) {
            hddSerial = hddSerial.substr(0, hddSerial.find(","));
        }

        // CPU brand is shared by many machines and cannot safely identify a
        // client by itself. Do not hash the same pair of fallback markers into
        // a reusable HWID when both device-specific WMI sources are unavailable.
        const bool hasMotherboardId =
            !motherboardUuid.empty() && motherboardUuid != "UNKNOWN";
        const bool hasDiskId =
            !hddSerial.empty() && hddSerial != "UNKNOWN";
        if (!hasMotherboardId && !hasDiskId) {
            return "";
        }

        // Keep the existing concatenation for valid source combinations so
        // existing, successfully generated HWIDs do not change.
        std::string combined = cpuBrand + motherboardUuid + hddSerial;
        return HashString(combined);
    }

    std::string HWIDGenerator::GetCpuBrand() {
        int cpuInfo[4] = { -1 };
        char cpuBrandString[0x40] = { 0 };

        // Dapatkan panjang string brand
        __cpuid(cpuInfo, 0x80000000);
        unsigned int nExIds = cpuInfo[0];

        // Dapatkan string brand
        memset(cpuBrandString, 0, sizeof(cpuBrandString));
        for (unsigned int i = 0x80000000; i <= nExIds; ++i) {
            __cpuid(cpuInfo, i);
            if (i == 0x80000002) memcpy(cpuBrandString, cpuInfo, sizeof(cpuInfo));
            else if (i == 0x80000003) memcpy(cpuBrandString + 16, cpuInfo, sizeof(cpuInfo));
            else if (i == 0x80000004) memcpy(cpuBrandString + 32, cpuInfo, sizeof(cpuInfo));
        }
        return std::string(cpuBrandString);
    }

    std::string HWIDGenerator::GetWmiProperty(const std::string& wmiClass, const std::string& wmiProperty) {
        HRESULT hres;
        std::string result = "UNKNOWN";

        // 1. Inisialisasi COM. S_FALSE juga menambah reference count COM
        // dan wajib diimbangi; RPC_E_CHANGED_MODE tidak boleh di-CoUninitialize.
        ScopedComInitialization comInitialization(COINIT_MULTITHREADED);
        if (!comInitialization.IsInitialized()) return result;

        // 2. Set security levels COM
        hres = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
        if (FAILED(hres) && hres != RPC_E_TOO_LATE) { return result; }

        // 3. Dapatkan pointer ke WbemLocator. Keep COM interfaces under RAII
        // so every error and exception path releases acquired references.
        IWbemLocator* locatorRaw = nullptr;
        hres = CoCreateInstance(
            CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator,
            reinterpret_cast<LPVOID*>(&locatorRaw));
        std::unique_ptr<IWbemLocator, ComRelease<IWbemLocator>> locator(locatorRaw);
        if (FAILED(hres) || !locator) return result;

        // 4. Hubungkan ke WMI.
        IWbemServices* servicesRaw = nullptr;
        hres = locator->ConnectServer(
            _bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, &servicesRaw);
        std::unique_ptr<IWbemServices, ComRelease<IWbemServices>> services(servicesRaw);
        if (FAILED(hres) || !services) return result;

        // 5. Set security levels untuk WMI connection.
        hres = CoSetProxyBlanket(
            services.get(), RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
            RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
        if (FAILED(hres)) return result;

        // 6. Gunakan WMI query.
        IEnumWbemClassObject* enumeratorRaw = nullptr;
        std::wstring query = L"SELECT " +
            std::wstring(wmiProperty.begin(), wmiProperty.end()) +
            L" FROM " + std::wstring(wmiClass.begin(), wmiClass.end());
        hres = services->ExecQuery(
            bstr_t("WQL"), bstr_t(query.c_str()),
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            NULL, &enumeratorRaw);
        std::unique_ptr<IEnumWbemClassObject, ComRelease<IEnumWbemClassObject>>
            enumerator(enumeratorRaw);
        if (FAILED(hres) || !enumerator) return result;

        // 7. Read only the first result and bound the wait for a slow/stalled provider.
        constexpr LONG kWmiEnumerationTimeoutMs = 10000;
        IWbemClassObject* objectRaw = nullptr;
        ULONG returned = 0;
        const HRESULT nextResult = enumerator->Next(
            kWmiEnumerationTimeoutMs, 1, &objectRaw, &returned);
        std::unique_ptr<IWbemClassObject, ComRelease<IWbemClassObject>>
            object(objectRaw);
        if (FAILED(nextResult) || returned != 1 || !object) return result;

        VARIANT propertyValue;
        VariantInit(&propertyValue);
        struct VariantClearGuard {
            VARIANT* value;
            ~VariantClearGuard() { VariantClear(value); }
        } propertyValueGuard{ &propertyValue };
        (void)propertyValueGuard;

        const HRESULT propertyResult = object->Get(
            _bstr_t(wmiProperty.c_str()), 0, &propertyValue, 0, 0);
        if (SUCCEEDED(propertyResult) &&
            propertyValue.vt == VT_BSTR && propertyValue.bstrVal != nullptr) {
            result = _bstr_t(propertyValue.bstrVal);
        }

        // COM interfaces and VARIANT are released/cleared automatically.
       

        return result;
    }

    std::string HWIDGenerator::HashString(const std::string& input) {
        // Kode hashing sama seperti di FileIntegrityChecker
        BCRYPT_ALG_HANDLE hAlg = NULL;
        BCRYPT_HASH_HANDLE hHash = NULL;
        NTSTATUS status = STATUS_UNSUCCESSFUL;
        DWORD cbHash = 0, cbHashObject = 0;
        PBYTE pbHashObject = NULL;
        PBYTE pbHash = NULL;

        status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
        if (!BCRYPT_SUCCESS(status)) { return ""; }
        DWORD cbData = 0;
        status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(DWORD), &cbData, 0);
        if (!BCRYPT_SUCCESS(status)) { BCryptCloseAlgorithmProvider(hAlg, 0); return ""; }
        status = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&cbHash, sizeof(DWORD), &cbData, 0);
        if (!BCRYPT_SUCCESS(status)) { BCryptCloseAlgorithmProvider(hAlg, 0); return ""; }

        pbHashObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHashObject);
        pbHash = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHash);
        if (!pbHashObject || !pbHash) { HeapFree(GetProcessHeap(), 0, pbHashObject); HeapFree(GetProcessHeap(), 0, pbHash); BCryptCloseAlgorithmProvider(hAlg, 0); return ""; }

        status = BCryptCreateHash(hAlg, &hHash, pbHashObject, cbHashObject, NULL, 0, 0);
        if (!BCRYPT_SUCCESS(status)) { HeapFree(GetProcessHeap(), 0, pbHashObject); HeapFree(GetProcessHeap(), 0, pbHash); BCryptCloseAlgorithmProvider(hAlg, 0); return ""; }
        status = BCryptHashData(hHash, (PBYTE)input.c_str(), (ULONG)input.length(), 0);
        if (!BCRYPT_SUCCESS(status)) { BCryptDestroyHash(hHash); HeapFree(GetProcessHeap(), 0, pbHashObject); HeapFree(GetProcessHeap(), 0, pbHash); BCryptCloseAlgorithmProvider(hAlg, 0); return ""; }
        status = BCryptFinishHash(hHash, pbHash, cbHash, 0);
        if (!BCRYPT_SUCCESS(status)) { BCryptDestroyHash(hHash); HeapFree(GetProcessHeap(), 0, pbHashObject); HeapFree(GetProcessHeap(), 0, pbHash); BCryptCloseAlgorithmProvider(hAlg, 0); return ""; }

        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (DWORD i = 0; i < cbHash; i++) { ss << std::setw(2) << static_cast<unsigned int>(pbHash[i]); }

        BCryptDestroyHash(hHash);
        HeapFree(GetProcessHeap(), 0, pbHashObject);
        HeapFree(GetProcessHeap(), 0, pbHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return ss.str();
    }
}