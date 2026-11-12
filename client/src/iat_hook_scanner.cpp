#include "pch.h"
#include "iat_hook_scanner.h"
#include <windows.h>
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>

namespace {
    bool IsReadableRange(const void* address, size_t length) {
        if (length == 0) return true;
        uintptr_t cursor = reinterpret_cast<uintptr_t>(address);
        if (cursor > (std::numeric_limits<uintptr_t>::max)() - length) return false;
        size_t remaining = length;

        while (remaining > 0) {
            MEMORY_BASIC_INFORMATION mbi{};
            if (VirtualQuery(reinterpret_cast<const void*>(cursor), &mbi, sizeof(mbi)) == 0)
                return false;
            if (mbi.State != MEM_COMMIT ||
                (mbi.Protect & PAGE_NOACCESS) != 0 ||
                (mbi.Protect & PAGE_GUARD) != 0) {
                return false;
            }

            const uintptr_t regionBase = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
            if (regionBase > cursor || mbi.RegionSize > (std::numeric_limits<uintptr_t>::max)() - regionBase)
                return false;
            const uintptr_t regionEnd = regionBase + mbi.RegionSize;
            if (regionEnd <= cursor) return false;

            const size_t available = static_cast<size_t>(regionEnd - cursor);
            const size_t step = (std::min)(remaining, available);
            cursor += step;
            remaining -= step;
        }
        return true;
    }

    bool HasImageRange(size_t imageSize, size_t rva, size_t length) {
        return rva <= imageSize && length <= imageSize - rva;
    }

    bool IsNullTerminatedInsideImage(const char* value, const BYTE* base,
                                     size_t imageSize, size_t rva) {
        if (rva >= imageSize) return false;
        const size_t remaining = imageSize - rva;
        if (!IsReadableRange(value, remaining)) return false;
        return std::memchr(value, '\\0', remaining) != nullptr;
    }

    void ReportIatMismatch(const char* functionName, const char* dllName) {
        std::wstring message = L"IAT Hook terdeteksi!\\n\\nFungsi: ";
        if (functionName) {
            while (*functionName) message.push_back(static_cast<unsigned char>(*functionName++));
        }
        message += L"\\nDLL: ";
        if (dllName) {
            while (*dllName) message.push_back(static_cast<unsigned char>(*dllName++));
        }
        message += L"\\n\\nClient akan ditutup.";
        MessageBoxW(NULL, message.c_str(), L"Oblivion Hack Shield - Violation",
                    MB_OK | MB_ICONERROR | MB_TOPMOST);
        ExitProcess(0);
    }
}

namespace Oblivion {
    IATHookScanner::IATHookScanner() {}
    IATHookScanner::~IATHookScanner() {}

    void IATHookScanner::PerformScan() {
        HMODULE module = GetModuleHandleW(NULL);
        if (!module) return;

        BYTE* const base = reinterpret_cast<BYTE*>(module);
        if (!IsReadableRange(base, sizeof(IMAGE_DOS_HEADER))) return;

        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE ||
            dos->e_lfanew < static_cast<LONG>(sizeof(IMAGE_DOS_HEADER)) ||
            dos->e_lfanew > 1024 * 1024) {
            return;
        }

        const size_t ntOffset = static_cast<size_t>(dos->e_lfanew);
        if (!IsReadableRange(base + ntOffset, sizeof(IMAGE_NT_HEADERS))) return;

        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + ntOffset);
        if (nt->Signature != IMAGE_NT_SIGNATURE ||
            nt->FileHeader.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER) ||
            nt->OptionalHeader.Magic !=
#if defined(_WIN64)
                IMAGE_NT_OPTIONAL_HDR64_MAGIC
#else
                IMAGE_NT_OPTIONAL_HDR32_MAGIC
#endif
            ) {
            return;
        }

        const size_t imageSize = static_cast<size_t>(nt->OptionalHeader.SizeOfImage);
        if (imageSize < sizeof(IMAGE_DOS_HEADER) ||
            !HasImageRange(imageSize, ntOffset, sizeof(IMAGE_NT_HEADERS))) {
            return;
        }

        if (nt->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_IMPORT)
            return;

        const IMAGE_DATA_DIRECTORY importDirectory =
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (importDirectory.VirtualAddress == 0 || importDirectory.Size < sizeof(IMAGE_IMPORT_DESCRIPTOR) ||
            !HasImageRange(imageSize, importDirectory.VirtualAddress, importDirectory.Size)) {
            return;
        }

        const size_t descriptorCount = importDirectory.Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
        const auto* descriptors = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(
            base + importDirectory.VirtualAddress);
        if (!IsReadableRange(descriptors, descriptorCount * sizeof(IMAGE_IMPORT_DESCRIPTOR)))
            return;

        bool foundTerminator = false;
        for (size_t descriptorIndex = 0; descriptorIndex < descriptorCount; ++descriptorIndex) {
            const IMAGE_IMPORT_DESCRIPTOR& descriptor = descriptors[descriptorIndex];
            if (descriptor.Name == 0) {
                foundTerminator = true;
                break;
            }

            const size_t dllNameRva = static_cast<size_t>(descriptor.Name);
            if (!HasImageRange(imageSize, dllNameRva, 1)) return;
            const char* dllName = reinterpret_cast<const char*>(base + dllNameRva);
            if (!IsNullTerminatedInsideImage(dllName, base, imageSize, dllNameRva)) return;

            HMODULE importedModule = GetModuleHandleA(dllName);
            if (!importedModule) continue;

            // OriginalFirstThunk can be zero in valid images; use FirstThunk as fallback.
            const size_t lookupRva = descriptor.OriginalFirstThunk != 0
                ? static_cast<size_t>(descriptor.OriginalFirstThunk)
                : static_cast<size_t>(descriptor.FirstThunk);
            const size_t iatRva = static_cast<size_t>(descriptor.FirstThunk);
            if (lookupRva == 0 || iatRva == 0 ||
                !HasImageRange(imageSize, lookupRva, sizeof(IMAGE_THUNK_DATA)) ||
                !HasImageRange(imageSize, iatRva, sizeof(IMAGE_THUNK_DATA))) {
                return;
            }

            const size_t maxLookupEntries =
                (imageSize - lookupRva) / sizeof(IMAGE_THUNK_DATA);
            const size_t maxIatEntries =
                (imageSize - iatRva) / sizeof(IMAGE_THUNK_DATA);
            const size_t maxEntries = (std::min)(maxLookupEntries, maxIatEntries);

            bool thunkTerminated = false;
            for (size_t thunkIndex = 0; thunkIndex < maxEntries; ++thunkIndex) {
                const size_t lookupOffset = lookupRva + thunkIndex * sizeof(IMAGE_THUNK_DATA);
                const size_t iatOffset = iatRva + thunkIndex * sizeof(IMAGE_THUNK_DATA);
                if (!IsReadableRange(base + lookupOffset, sizeof(IMAGE_THUNK_DATA)) ||
                    !IsReadableRange(base + iatOffset, sizeof(IMAGE_THUNK_DATA))) {
                    return;
                }

                const auto* lookupThunk = reinterpret_cast<const IMAGE_THUNK_DATA*>(base + lookupOffset);
                const auto* iatThunk = reinterpret_cast<const IMAGE_THUNK_DATA*>(base + iatOffset);
                if (lookupThunk->u1.AddressOfData == 0) {
                    thunkTerminated = true;
                    break;
                }

                if ((lookupThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) != 0) continue;

                const uint64_t importNameValue =
                    static_cast<uint64_t>(lookupThunk->u1.AddressOfData);
                if (importNameValue > imageSize ||
                    !HasImageRange(imageSize, static_cast<size_t>(importNameValue),
                                   sizeof(WORD) + 1)) {
                    return;
                }

                const size_t importNameRva = static_cast<size_t>(importNameValue);
                const char* functionName = reinterpret_cast<const char*>(
                    base + importNameRva + sizeof(WORD));
                if (!IsNullTerminatedInsideImage(functionName, base, imageSize,
                                                 importNameRva + sizeof(WORD))) {
                    return;
                }

                FARPROC realAddress = GetProcAddress(importedModule, functionName);
                if (!realAddress) continue;

                const FARPROC iatAddress = reinterpret_cast<FARPROC>(
                    static_cast<ULONG_PTR>(iatThunk->u1.Function));
                if (iatAddress != realAddress) {
                    ReportIatMismatch(functionName, dllName);
                    return;
                }
            }

            // A malformed lookup table with no terminator is rejected rather than over-read.
            if (!thunkTerminated) return;
        }

        // If the bounded import directory does not contain its zero terminator,
        // the PE metadata is malformed. Do not continue reading beyond it.
        if (!foundTerminator) return;
    }
}
