#include <iostream>
#include <thread>
#include "memory.h"
#include "offsets.h"

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
        // Implement your shit here

        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    return 0;
}
