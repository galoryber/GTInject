using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;

namespace GTInject.Injection
{
    internal class threadexec
    {
        public static IntPtr SelectThreadOption(IntPtr memaddr, int execoption, int pid, int tid)
        {
            switch (execoption)
            {
                case 1:
                    return execopt1(memaddr, pid, tid);
                    break;
                case 2:
                    return IntPtr.Zero;
                    break;
            }
            return IntPtr.Zero;
        }

        private static IntPtr execopt1(IntPtr memaddr, Process ProcID, int ThreadID)
        {
            // //  GTInject.exe inject memoryOption execOption xorkey binSrcType binSourcePath PID TID
            /////////////////////////////////////
            // OPTION 1 == CreateRemoteThread (WINAPI)
            /////////////////////////////////////
            
            IntPtr remoteThreadResp = CreateRemoteThread(ProcID.handle, (IntPtr)0, 0, memaddr, (IntPtr)0, 0, (IntPtr)0);
            return remoteThreadResp;
        }

        /////////////////////////////////////
        // Supporting functions
        /////////////////////////////////////


        /////////////////////////////////////
        // PInvokes and Enums / Structures
        /////////////////////////////////////
        [DllImport("kernel32.dll")]
        public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);


    }
}
