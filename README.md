<h1># revrbe-better-memory</h1>

Functional memory header for opening handle, getting modules and read/writing to process. 

Currently its using NtOpenProcess to open a handle to the process and then NtReadVirtualMemory and NtWriteVirtualMemory to perform memory operations.

<h2>Features and to-do</h2>

✅ Bunnyhop

✅ Clean modern C++ code

✅ Memory operations (read/write) 

✅ NtOpenProcess, NtReadVirtualMemory & NtWriteVirtualMemory syscalls

✅ Polymorphism

✅ Dynamically loading Native API functions and ntdll.dll library (JIT)

❌ Changing the rest of the Windows API functions to Native API functions(CreateToolhelp32Snapshot, Process32Next, Module32Next, ProcessIdToSessionId, GetModuleHandle & GetProcAddress)

<h2>Usage</h2>

Currently only bhop, but compile and run the executable. 

Only tested on Windows 10 21H2

<b>Warning:</b> This is for educational purposes only. Using this in-game might result in a ban. Use at your own risk!

<h3>Personal Note</h3>

Was too bored to implement any actual cheat features, but tested with simple bunny-hop and it works fine. For extra security; I recommend using Themida, VMProtect or Enigma.

Discord: revrbe

<h4>Update</h4>
I fixed the code, so it works better than before. Also I removed the XOR encryption on the memory operations, but will probably re-add it again soon with a more reliable implementation.

I also added NtReadVirtualMemory and NtWriteVirtualMemory instead of Windows API counterparts and also made necessary functions and libraries dynamically loaded using JIT techniques.
