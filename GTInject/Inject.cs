using CommandLine.Text;
using CommandLine;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

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
        public class Options
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

        }


        static void Main(string[] args)
        {
            Parser.Default.ParseArguments<Inject.Options>(args)
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
           });

            // Should parse args, then build each function seperately. 
        }
    }
}
