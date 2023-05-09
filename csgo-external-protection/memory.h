#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <stdexcept>
#include <cstdint>
#include <string_view>
#include <memory>
#include <concepts>
#include <vector>
#include <random>

class XorCipher {
public:
    static std::vector<uint8_t> Encrypt(const std::vector<uint8_t>& data, const std::string& key) {
        std::vector<uint8_t> encryptedData(data.size());

        for (size_t i = 0; i < data.size(); ++i) {
            encryptedData[i] = data[i] ^ key[i % key.size()];
        }

        return encryptedData;
    }

    static std::vector<uint8_t> Decrypt(const std::vector<uint8_t>& encryptedData, const std::string& key) {
        return Encrypt(encryptedData, key); 
    }
};

class MemInterface
{
private:
    std::string XOR_key; 
public:
    MemInterface() {
        XOR_key = GenerateKey(24); 
    }

    std::string GenerateKey(int length) {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(33, 126); 

        std::string key;
        for (int n = 0; n < length; ++n)
            key.push_back(static_cast<char>(dis(gen)));

        return key;
    }

    virtual ~MemInterface() = default;
    virtual std::uintptr_t GetModuleAddress(const std::string_view moduleName) const noexcept = 0;
    virtual bool IsValid() const noexcept = 0;

    template <typename T>
        requires std::is_trivially_copyable_v<T>
    constexpr const T Read(const std::uintptr_t& address) const noexcept
    {
        T value = {};
        std::vector<uint8_t> rawData(sizeof(T));
        ReadProcessMemory(GetProcessHandle(), reinterpret_cast<const void*>(address), rawData.data(), rawData.size(), nullptr);
        auto decryptedData = XorCipher::Decrypt(rawData, XOR_key);

        std::memcpy(&value, decryptedData.data(), sizeof(T));
        return value;
    }

    template <typename T>
        requires std::is_trivially_copyable_v<T>
    constexpr void Write(const std::uintptr_t& address, const T& value) const noexcept
    {
        std::vector<uint8_t> rawData(sizeof(T));
        std::memcpy(rawData.data(), &value, sizeof(T));
        auto encryptedData = XorCipher::Encrypt(rawData, XOR_key);

        WriteProcessMemory(GetProcessHandle(), reinterpret_cast<void*>(address), encryptedData.data(), encryptedData.size(), nullptr);
    }

protected:
    virtual void* GetProcessHandle() const noexcept = 0;
};

class Memory : public MemInterface
{
private:
    std::uintptr_t processId = 0;
    void* processHandle = nullptr;

public:
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

                pNtOpenProcess NtOpenProcess = (pNtOpenProcess)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtOpenProcess");
                if (NtOpenProcess) {
                    OBJECT_ATTRIBUTES oa = { sizeof(OBJECT_ATTRIBUTES) };
                    CLIENT_ID ci = { (HANDLE)processId, 0 };
                    NtOpenProcess(&processHandle, PROCESS_ALL_ACCESS, &oa, &ci);
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
        return processHandle != nullptr;
    }

protected:
    void* GetProcessHandle() const noexcept override
    {
        return processHandle;
    }
};
