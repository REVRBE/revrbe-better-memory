#include <iostream>
#include <thread>
#include "memory.h"
#include "offsets.h"

void bunnyhop(Memory& mem, std::uintptr_t clientDLL, std::uintptr_t localPlayer) {
    int flags = mem.Read<int>(localPlayer + hazedumper::netvars::m_fFlags);

    if (GetAsyncKeyState(VK_SPACE) & 0x8000) {
        if (flags & (1 << 0)) {
            mem.Write<int>(clientDLL + hazedumper::signatures::dwForceJump, 6);
        }
        else {
            mem.Write<int>(clientDLL + hazedumper::signatures::dwForceJump, 4);
        }
    }
}

int main()
{
    Memory mem("csgo.exe");

    if (!mem.IsValid()) {
        std::cerr << "[-] Failed to obtain a handle to csgo.exe" << std::endl;
        return 1;
    }

    std::uintptr_t clientDLL = mem.GetModuleAddress("client.dll");
    if (!clientDLL) {
        std::cerr << "[-] Failed to obtain the base address of client.dll" << std::endl;
        return 1;
    }
    std::cout << "[$] Base address of client.dll: 0x" << std::hex << clientDLL << std::endl;

    std::uintptr_t engineDLL = mem.GetModuleAddress("engine.dll");
    if (!engineDLL) {
        std::cerr << "[-] Failed to obtain the base address of engine.dll" << std::endl;
        return 1;
    }
    std::cout << "[$] Base address of engine.dll: 0x" << std::hex << engineDLL << std::endl;


    while (true) {
        std::uintptr_t localPlayer = mem.Read<std::uintptr_t>(clientDLL + hazedumper::signatures::dwLocalPlayer);

        bunnyhop(mem, clientDLL, localPlayer);

        Sleep(25);
    }

    return 0;
}
