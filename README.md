# GTInject
Build re-usable process injection for multiple C2s. Based off of design of BRC4. 



## GTInject.exe Help Menu

## Usage: GTInject.exe <command> <commandArgs>
       GTInject.exe threads
       GTInject.exe encrypt pathToSource.bin MySecretXorKey
       GTInject.exe inject memoryOption execOption xorkey binSrcType binSourcePath PID TID

       GTInject.exe inject 1 1 SecretKey123 disk "C:\path\to\xordShellcode.file" 1234 321

## Encrypt  -- for encrypting shellcode:
        Shellcode from your C2 will be multibyte XOR'd and written as a base64 string in a text file
        This is intended to help you use the injection option later
        This is also my utility for encrypting payloads to be used in shellcode runners

        Do this in preparation, not on the C2 victim machine.

## Threads  -- check for alertable threads:
        This will list all threads and their current execution state
        This is intended to help identify alertable threads, for injection options.

## Inject   -- choose a process injection method
        Choose a technique for allocating the memory
        Then choose a technique for executing the thread
        Enter the XorKey to decrypt it with
        Specify a location type where the encrypted shellcode is stored 
        Specify the location
        Specify the PID
        OPTIONALLY specify the TID (not all options need a Thread ID)

## Memory Options
        1. WINAPI -- VirtualAllocEx, WriteProcessMemory
        2. WINAPI -- MapViewOfSection, WriteProcessMemory

## ThreadExec Options
        1. WINAPI -- CreateRemoteThread

# ToDo
* In the Alertable Threads function - bring in integrity - filter based on AppContainers - have option to show all anyway
* Better ReadMe
* Add Sleep / Delay function, determine where delay should happen ... set to 30 seconds, memory allocation will happen, wait 30, then exec option will proceed. or between each API call? add Jitter/multiplier? so user selects 10 seconds, 3x and it will wait at least 10 seconds, and up to 30 seconds between execution?
