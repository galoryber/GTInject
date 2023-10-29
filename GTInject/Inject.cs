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
        [Option('t', "threads", Required = false, HelpText = "Show all threads in an alertable state.", Default = false)]
        public bool threads { get; set; }
        static void Main(string[] args)
        {
            Parser.Default.ParseArguments<Inject>(args)
           .WithParsed<Inject>(o =>
           {
               if (o.threads)
               {
                   AlertableThreads.Alertable.GetThreads();
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
