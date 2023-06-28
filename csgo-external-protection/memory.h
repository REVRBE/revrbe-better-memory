#ifndef MEMORY_H
#define MEMORY_H

#include <Windows.h>
#include <TlHelp32.h>
#include <stdexcept>
#include <cstdint>
#include <string_view>
#include <memory>
#include <concepts>
#include <vector>
#include <iostream>

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING;

typedef UNICODE_STRING* PUNICODE_STRING;

typedef const UNICODE_STRING* PCUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES;

typedef OBJECT_ATTRIBUTES* POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef NTSTATUS(NTAPI* pNtOpenProcess)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);
typedef NTSTATUS(NTAPI* pNtReadVirtualMemory)(HANDLE, PVOID, PVOID, ULONG_PTR, PULONG_PTR);
typedef NTSTATUS(NTAPI* pNtWriteVirtualMemory)(HANDLE, PVOID, PVOID, ULONG_PTR, PULONG_PTR);

FARPROC GetProcAddressJIT(HMODULE hModule, LPCSTR lpProcName);
HMODULE LoadLibraryJIT(const char* lpFileName);

class MemInterface
{
private:
    pNtReadVirtualMemory NtReadVirtualMemory = nullptr;
    pNtWriteVirtualMemory NtWriteVirtualMemory = nullptr;

public:
    MemInterface()
    {
        HMODULE ntdllModule = LoadLibraryJIT("ntdll.dll");
        if (ntdllModule)
        {
            NtReadVirtualMemory = reinterpret_cast<pNtReadVirtualMemory>(GetProcAddressJIT(ntdllModule, "NtReadVirtualMemory"));
            NtWriteVirtualMemory = reinterpret_cast<pNtWriteVirtualMemory>(GetProcAddressJIT(ntdllModule, "NtWriteVirtualMemory"));
            if (!NtReadVirtualMemory || !NtWriteVirtualMemory)
            {
                std::cerr << "[-] Failed to get the address of NtReadVirtualMemory or NtWriteVirtualMemory" << std::endl;
            }
        }
        else
        {
            std::cerr << "[-] Failed to load ntdll.dll" << std::endl;
        }
    }

    virtual ~MemInterface() = default;
    virtual std::uintptr_t GetModuleAddress(const std::string_view moduleName) const noexcept = 0;
    virtual bool IsValid() const noexcept = 0;

    template <typename T>
        requires std::is_trivially_copyable_v<T>
    const T Read(const std::uintptr_t& address) const noexcept
    {
        if constexpr (std::is_pointer_v<T>)
        {
            std::remove_pointer_t<T> value{};
            if (NtReadVirtualMemory)
            {
                NtReadVirtualMemory(GetProcessHandle(), reinterpret_cast<PVOID>(address), &value, sizeof(value), nullptr);
            }
            return reinterpret_cast<T>(value);
        }
        else
        {
            T value{};
            if (NtReadVirtualMemory)
            {
                NtReadVirtualMemory(GetProcessHandle(), reinterpret_cast<PVOID>(address), &value, sizeof(value), nullptr);
            }
            return value;
        }
    }

    template <typename T>
        requires std::is_trivially_copyable_v<T>
    void Write(const std::uintptr_t& address, const T& value) const noexcept
    {
        DWORD oldProtect;
        if (VirtualProtectEx(GetProcessHandle(), reinterpret_cast<void*>(address), sizeof(T), PAGE_EXECUTE_READWRITE, &oldProtect))
        {
            if constexpr (std::is_pointer_v<T>)
            {
                auto valueCopy = reinterpret_cast<std::uintptr_t>(*const_cast<T*>(&value));  // If it's a pointer, reinterpret_cast it
                ULONG_PTR sizeWritten;
                if (NtWriteVirtualMemory)
                {
                    NtWriteVirtualMemory(GetProcessHandle(), reinterpret_cast<PVOID>(address), reinterpret_cast<PVOID>(valueCopy), sizeof(valueCopy), &sizeWritten);
                }
            }
            else
            {
                ULONG_PTR sizeWritten;
                if (NtWriteVirtualMemory)
                {
                    NtWriteVirtualMemory(GetProcessHandle(), reinterpret_cast<PVOID>(address), const_cast<T*>(&value), sizeof(T), &sizeWritten);
                }
            }

            VirtualProtectEx(GetProcessHandle(), reinterpret_cast<void*>(address), sizeof(T), oldProtect, nullptr);
        }
        else
        {
            // std::cerr << "[-] Failed to change memory protection at address 0x" << std::hex << address << std::endl;
        }
    }

protected:
    virtual HANDLE GetProcessHandle() const noexcept = 0;
};

class Memory : public MemInterface
{
private:
    std::uintptr_t processId = 0;
    HANDLE processHandle = nullptr;
    HMODULE ntdllModule = nullptr;
    pNtOpenProcess NtOpenProcess = nullptr;
    pNtReadVirtualMemory NtReadVirtualMemory = nullptr;
    pNtWriteVirtualMemory NtWriteVirtualMemory = nullptr;

public:
    Memory(const std::string_view processName) noexcept
    {
        ::PROCESSENTRY32 entry = {};
        entry.dwSize = sizeof(::PROCESSENTRY32);

        const auto snapShot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

        while (::Process32Next(snapShot, &entry))
        {
            if (!processName.compare(entry.szExeFile))
            {
                processId = entry.th32ProcessID;

                ntdllModule = LoadLibraryJIT("ntdll.dll");
                if (ntdllModule)
                {
                    NtOpenProcess = reinterpret_cast<pNtOpenProcess>(GetProcAddressJIT(ntdllModule, "NtOpenProcess"));
                    NtReadVirtualMemory = reinterpret_cast<pNtReadVirtualMemory>(GetProcAddressJIT(ntdllModule, "NtReadVirtualMemory"));
                    NtWriteVirtualMemory = reinterpret_cast<pNtWriteVirtualMemory>(GetProcAddressJIT(ntdllModule, "NtWriteVirtualMemory"));
                    if (NtOpenProcess && NtReadVirtualMemory && NtWriteVirtualMemory)
                    {
                        OBJECT_ATTRIBUTES oa = { sizeof(OBJECT_ATTRIBUTES) };
                        CLIENT_ID ci = { (HANDLE)processId, 0 };
                        NTSTATUS ntStatus = NtOpenProcess(&processHandle, PROCESS_ALL_ACCESS, &oa, &ci);
                        if (ntStatus >= 0)
                        {
                            std::cout << "[+] NtOpenProcess succeeded" << std::endl;
                        }
                        else
                        {
                            std::cerr << "[-] NtOpenProcess failed with status: " << std::hex << ntStatus << std::endl;
                        }
                    }
                    else
                    {
                        std::cerr << "[-] Failed to get the address of NtOpenProcess, NtReadVirtualMemory, or NtWriteVirtualMemory" << std::endl;
                    }
                }
                else
                {
                    std::cerr << "[-] Failed to load ntdll.dll" << std::endl;
                }

                break;
            }
        }

        if (snapShot) {
            ::CloseHandle(snapShot);
        }
    }

    ~Memory()
    {
        if (processHandle) {
            ::CloseHandle(processHandle);
        }
        if (ntdllModule) {
            ::FreeLibrary(ntdllModule);
        }
    }

    std::uintptr_t GetModuleAddress(const std::string_view moduleName) const noexcept override
    {
        ::MODULEENTRY32 entry = {};
        entry.dwSize = sizeof(::MODULEENTRY32);

        const auto snapShot = ::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);

        std::uintptr_t result = 0;

        DWORD sessionId;
        if (!::ProcessIdToSessionId(processId, &sessionId))
        {
            return result;
        }

        DWORD currentSessionId;
        if (!::ProcessIdToSessionId(::GetCurrentProcessId(), &currentSessionId))
        {
            return result;
        }

        if (sessionId == currentSessionId)
        {
            while (::Module32Next(snapShot, &entry))
            {
                if (!moduleName.compare(entry.szModule))
                {
                    result = reinterpret_cast<std::uintptr_t>(entry.modBaseAddr);
                    break;
                }
            }
        }

        if (snapShot)
            ::CloseHandle(snapShot);

        return result;
    }

    bool IsValid() const noexcept override
    {
        return processHandle != nullptr && ntdllModule != nullptr && NtOpenProcess != nullptr && NtReadVirtualMemory != nullptr && NtWriteVirtualMemory != nullptr;
    }

protected:
    HANDLE GetProcessHandle() const noexcept override
    {
        return processHandle;
    }
};

// Helper functions
FARPROC GetProcAddressJIT(HMODULE hModule, LPCSTR lpProcName)
{
    auto dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(hModule);
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return nullptr;

    auto ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(reinterpret_cast<const std::uint8_t*>(hModule) + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
        return nullptr;

    auto exportDirectory = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(reinterpret_cast<const std::uint8_t*>(hModule) + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    auto nameTable = reinterpret_cast<const std::uint32_t*>(reinterpret_cast<const std::uint8_t*>(hModule) + exportDirectory->AddressOfNames);
    auto ordinalTable = reinterpret_cast<const std::uint16_t*>(reinterpret_cast<const std::uint8_t*>(hModule) + exportDirectory->AddressOfNameOrdinals);
    auto functionTable = reinterpret_cast<const std::uint32_t*>(reinterpret_cast<const std::uint8_t*>(hModule) + exportDirectory->AddressOfFunctions);

    for (std::size_t i = 0; i < exportDirectory->NumberOfNames; ++i)
    {
        auto functionName = reinterpret_cast<const char*>(reinterpret_cast<const std::uint8_t*>(hModule) + nameTable[i]);
        if (std::strcmp(functionName, lpProcName) == 0)
        {
            auto functionAddress = reinterpret_cast<const std::uint8_t*>(hModule) + functionTable[ordinalTable[i]];
            return reinterpret_cast<FARPROC>(functionAddress);
        }
    }

    return nullptr;
}

HMODULE LoadLibraryJIT(const char* lpFileName)
{
    std::size_t fileNameLength = std::strlen(lpFileName);
    std::unique_ptr<char[]> buffer(new char[fileNameLength + 1]);

    // Copy the filename to a local buffer and convert it to lowercase
    for (std::size_t i = 0; i < fileNameLength; ++i)
    {
        buffer[i] = std::tolower(lpFileName[i]);
    }
    buffer[fileNameLength] = '\0';

    // Check if the module is already loaded
    HMODULE hModule = GetModuleHandleA(buffer.get());
    if (hModule)
        return hModule;

    // Load the module using LoadLibraryA
    return LoadLibraryA(lpFileName);
}

#endif
