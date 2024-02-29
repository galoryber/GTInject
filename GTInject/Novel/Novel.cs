using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace GTInject.Novel
{
    internal class Novel
    {
        public static (IntPtr, Process) SelectNovelMemOption(int memoption, string xorkey, string binsrctype, string binsrcpath, int pid, int tid)
        {
            switch (memoption)
            {
                case 400:
                    return novelMem400(binsrctype, binsrcpath, xorkey, pid);
                case 401:
                    return novelMem401(binsrctype, binsrcpath, xorkey, pid);
                default:
                    Console.WriteLine("[-] Not a valid novel mem technique integer");
                    return (IntPtr.Zero, null);
            }

        }

        public static IntPtr SelectNovelExecOption(int execoption, string xorkey, string binsrctype, string binsrcpath, int pid, int tid)
        {
            switch (execoption)
            {
                case 400:
                    return novelExec400(binsrctype, binsrcpath, xorkey, pid);
                case 401:
                    return novelExec401(binsrctype, binsrcpath, xorkey, pid);
                default:
                    Console.WriteLine("[-] Not a valid novel exec technique integer");
                    return (IntPtr.Zero);
            }

        }

        // NOVEL MEMORY OPTIONS

        private static (IntPtr, Process) novelMem400(string binLocation, string bytePath, string xorkey, int ProcID)
        {
            // //  GTInject.exe inject memoryOption execOption xorkey binSrcType binSourcePath PID TID
            /////////////////////////////////////
            // OPTION 400 == MockingJay RWX - TBD
            /////////////////////////////////////
            return (IntPtr.Zero, null);

        }
        private static (IntPtr, Process) novelMem401(string binLocation, string bytePath, string xorkey, int ProcID)
        {
            // //  GTInject.exe inject memoryOption execOption xorkey binSrcType binSourcePath PID TID
            /////////////////////////////////////
            // OPTION 401 == MockingJay RWX - TBD
            /////////////////////////////////////
            return (IntPtr.Zero, null);

        }

        // NOVEL EXECUTION OPTIONS

        private static IntPtr novelExec400(string binLocation, string bytePath, string xorkey, int ProcID)
        {
            // //  GTInject.exe inject memoryOption execOption xorkey binSrcType binSourcePath PID TID
            /////////////////////////////////////
            // OPTION 400 == Threadless Inject - CreateEventW
            /////////////////////////////////////
            ///
            ThreadlessInject.Inject(ProcID, "kernelbase.dll", "CreateEventW", binLocation, bytePath, xorkey);
            return (IntPtr.Zero);
        }

        private static IntPtr novelExec401(string binLocation, string bytePath, string xorkey, int ProcID)
        {
            // //  GTInject.exe inject memoryOption execOption xorkey binSrcType binSourcePath PID TID
            /////////////////////////////////////
            // OPTION 400 == Threadless Inject - LoadLibraryExW
            /////////////////////////////////////
            ThreadlessInject.Inject(ProcID, "kernel32.dll", "LoadLibraryExW", binLocation, bytePath, xorkey);
            return (IntPtr.Zero);

        }

    }
}
