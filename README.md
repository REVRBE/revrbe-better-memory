<h1># revrbe-better-memory</h1>

Functional memory header for opening handle, getting modules and read/writing to process. Currently it is using NtOpenProcess to open a handle to csgo.exe and XOR encryption on memory read/write operations with randomized XOR key. 

<h2>Features</h2>

✅ Memory operations (read/write) XOR-encrypted with random key

✅ Direct system call to NtOpenProcess instead of using Windows API's OpenProcess(ReadProcessMemory, WriteProcessMemory, CreateToolhelp32Snapshot, Process32Next, Module32Next, ProcessIdToSessionId, GetModuleHandle & GetProcAddress)

✅ Polymorphism

❌ Changing the rest of the Windows API functions to Native API functions(

<h2>Usage</h2>

Implement your own cheat features and boom, it's a functional cheat.

Only tested on Windows 10 21H2

<b>Warning:</b> This is for educational purposes only. Using this in-game might result in a ban. Use at your own risk!

<h3>Personal Note</h3>

Was too bored to implement any actual cheat features, but tested with simple bunny-hop and it works fine.

Contact: REVRBE#7036
