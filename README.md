<h1># revrbe-better-memory</h1>

Functional memory header for opening handle, getting modules and read/writing to process. 

Currently it is using NtOpenProcess to open a handle to the process/game.

<h2>Features and to-do</h2>

✅ Bunnyhop

✅ Clean modern C++ code

✅ Memory operations (read/write) 

✅ Direct system call to NtOpenProcess instead of using Windows API's OpenProcess

✅ Polymorphism

❌ Changing the rest of the Windows API functions to Native API functions(ReadProcessMemory, WriteProcessMemory, CreateToolhelp32Snapshot, Process32Next, Module32Next, ProcessIdToSessionId, GetModuleHandle & GetProcAddress)

<h2>Usage</h2>

Currently only bhop, but compile and run the executable. 

Only tested on Windows 10 21H2

<b>Warning:</b> This is for educational purposes only. Using this in-game might result in a ban. Use at your own risk!

<h3>Personal Note</h3>

Was too bored to implement any actual cheat features, but tested with simple bunny-hop and it works fine. For extra security; I recommend using Themida, VMProtect or Enigma.

Contact: REVRBE#7036

<h4>Update</h4>
I fixed the code, so it works better than before. Also I removed the XOR encryption on the memory operations, but will probably re-add it again soon with a more reliable implementation.
