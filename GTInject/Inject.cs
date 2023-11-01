using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Globalization;

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
       /* public class Options
        {
            [Option('t', "threads", Required = false, HelpText = "Show all threads in an alertable state.", Default = false)]
            public bool threads { get; set; }

            [Option('e', "encrypt", Required = false, HelpText = "Encrypt your raw shellcode for later use within GTInject", Default = false)]
            public bool encrypt { get; set; }

            [Option('b', "sourcebin", Required = false, HelpText = "Select the source bin file (raw shellcode file) to encrypt")]
            public string binPath { get; set; }

            [Option('m', "memory", Required = false, HelpText = "Select the memory allocation option", Default = 1)]
            public int memoryoption { get; set; }

            [Option('x', "execution", Required = false, HelpText = "Select the thread execution method", Default = 1)]
            public int threadexecution { get; set; }

            [Option('p', "pid", Required = false, HelpText = "Process ID to inject into")]
            public int pid2inject { get; set; }

            [Option('s', "source", Required = false, HelpText = "Select a source location for the shellcode")]
            public string sourceShellcode { get; set; }
            //enum.parse later

            [Option('k', "xorkey", Required = false, HelpText = "Enter the xor key used to encrypt the shellcode")]
            public string xorkey { get; set; }

            [Option('h', "help", Required = false, HelpText = "Show the help menu", Default = false)]
            public bool help { get; set; } 

        }*/


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
       GTInject.exe encrypt pathToSource.bin MyXorKeySecret123
       GTInject.exe inject memoryOption execOption xorkey url binSourcePath

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
                Console.WriteLine(  "build the cool stuff here");
            }
            /*rser.Default.ParseArguments<Inject.Options>(args)
           .WithParsed<Inject.Options>(o =>
           {
               if (o.threads)
               {
                   AlertableThreads.Alertable.GetThreads();
               }
               else if (o.encrypt)
               {
                   if (o.binPath == null || o.xorkey == null) { Console.WriteLine(" Supplied the encrypt flag without supplying the source bin and output bin name (-e -b shellcode.bin -k myXorKey)"); }
                   EncryptBin.EncryptBin.EncryptShellcode(o.binPath, o.xorkey);
               }
               else
               {
                   Console.WriteLine($"Current Arguments: ");
                   Console.WriteLine("Quick Start Example!");
               }
           });*/

            // Should parse args, then build each function seperately. 
        }
    }
}
