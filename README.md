# GTInject
**Portable and Modular Process Injection**

Process injection in C2 frameworks are often limited to one or two techniques built by the beacon developer. This tool is designed to offer mix and match memory allocation and thread execution techniques for process injection, with the goal of being portable accross C2 systems. 

It is largely inspired by the flexibility given within Brute Ratel, which made other C2 injection options feel extremely limited. I wanted to recreate that functionality for other C2s that I like using. 



## GTInject.exe Help Menu

## Usage: GTInject.exe \<module> \<moduleArgs>
       GTInject.exe threads
       GTInject.exe encrypt pathToSource.bin MySecretXorKey
       GTInject.exe inject memoryOption execOption xorkey binSrcType binSourcePath PID TID

       GTInject.exe inject 100 100 SecretKey123 disk "C:\path\to\xordShellcode.file" 1234 321

## Encrypt  -- for encrypting shellcode:
**Do this in preparation, NOT on the C2 victim machine.**

       GTInject.exe encrypt pathToSource.bin MySecretXorKey

Shellcode from your C2 will be multibyte XOR'd and written in various formats.

This is intended to help you use the injection option later with better OpSec.

## Threads  -- check for alertable threads:

       GTInject.exe threads


This will list all threads and their current execution state.

This is intended to help identify alertable threads, for injection options like QueueUserAPC.
It will show processes you have access to, and any threads in the following states:
- Wait
- Suspended
- Delay Execution



## Inject   -- choose a process injection method

       GTInject.exe inject memoryOption execOption xorkey binSrcType binSourcePath PID TID

       GTInject.exe inject 100 100 SecretKey123 disk "C:\path\to\xordShellcode.file" 1234 321

Choose a technique for allocating the memory from your options below.

Then choose a technique for executing the thread from your options below.

Enter the XorKey to decrypt it with, the same one you used to encrypt the shellcode earlier.

Specify a location type where the encrypted shellcode is stored. Acceptable values are
- disk
- url
- embedded

Specify the path to that shellcode
- "C:\path\to\shellcode.file"
- https://example.com/shellcode.b64file
- 0 (embedded)

Specify the PID you want to inject into.

OPTIONALLY specify the TID (not all options need a Thread ID).

## Call Categories
- 100 Series - WINAPI
- 200 Series - NTAPI 
- 300 Series - Syscalls
- 400 Series - Misc Techniques

## Memory Options
        100. WINAPI -- VirtualAllocEx, WriteProcessMemory
        200. NTAPI  -- NtCreateSection, NtMapViewOfSection, RtlCopyMemory
        201. NTAPI  -- NtAllocateVirtualMemory, NtProtectVirtualMemory, NtWriteVirtualMemory

## ThreadExec Options
        100. WINAPI -- CreateRemoteThread
        101. WINAPI -- QueueUserAPC, ResumeThread
        200. NTAPI  -- NtCreateThreadEx
        201. NTAPI  -- RtlCreateUserThread
        202. NTAPI  -- NtQueueApcThread, NtResumeThread

# ToDo
* Obvious add more techniques
* In the Alertable Threads function - bring in integrity - filter based on AppContainers - have option to show all anyway
* Better ReadMe
* Add Sleep / Delay function, determine where delay should happen ... set to 30 seconds, memory allocation will happen, wait 30, then exec option will proceed. or between each API call? add Jitter/multiplier? so user selects 10 seconds, 3x and it will wait at least 10 seconds, and up to 30 seconds between execution?
