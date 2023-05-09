# revrbe-better-memory
Functional memory header for opening handle, getting modules and read/writing to process.

Currently it is using NtOpenProcess to open a handle to csgo.exe and XOR encryption on memory read/write with randomized XOR key on each run.
