using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using static GTInject.SysCalls.WinNative;

namespace GTInject.Util
{
    internal class CreateModule
    {

        public static PROCESS_INFORMATION CreateSuspendedProcess(string commandPath)
        {
            STARTUPINFO startupInfo = new STARTUPINFO();
            PROCESS_INFORMATION processInfo = new PROCESS_INFORMATION();

            if (!CreateProcess(
                null,
                commandPath,
                IntPtr.Zero,
                IntPtr.Zero,
                false,
                ProcessCreationFlags.CREATE_SUSPENDED,
                IntPtr.Zero,
                null,
                ref startupInfo,
                out processInfo))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            Console.WriteLine("  PROCESS_INFORMATION -> process ID " + processInfo.dwProcessId + " and handle in decimal " + processInfo.hProcess);
            return processInfo;
        }



        public static IntPtr CreateSuspendedThread(uint processId, IntPtr startAddress)
        {
            IntPtr hProcess = OpenProcess(
                ProcessAccess.CreateThread |
                ProcessAccess.QueryInformation |
                ProcessAccess.VmOperation |
                ProcessAccess.VmRead |
                ProcessAccess.VmWrite,
                false, processId);

            if (hProcess == IntPtr.Zero)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            IntPtr hThread = CreateRemoteThread(
                hProcess,
                IntPtr.Zero,
                0,
                startAddress,
                IntPtr.Zero,
                0x00000004, // CREATE_SUSPENDED
                IntPtr.Zero);

            if (hThread == IntPtr.Zero)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            var newThreadID = GetThreadId(hThread);
            Console.WriteLine("Process {0} now has Thread ID {1} ", processId, newThreadID );
            return hThread;
        }

        // TODO: If possible, create other wait state threads - like DeleyExecution state threads
        // DelayExecution is what it sounds like - basiclaly just means something is sleeping for a time. 
        // Create thread with thread flags "immediate exectuion" but have the start address resolve to kernel32!Sleep for a defined time
        // Thread should start and be waiting

        public static IntPtr CreateDelayedExecutionThread(uint processId)
        {
            IntPtr hProcess = OpenProcess(
                ProcessAccess.CreateThread |
                ProcessAccess.QueryInformation |
                ProcessAccess.VmOperation |
                ProcessAccess.VmRead |
                ProcessAccess.VmWrite,
                false, processId);

            if (hProcess == IntPtr.Zero)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            // Get the address of the Sleep function in the kernel32.dll
            IntPtr sleepAddress = GetProcAddress(GetModuleHandle("kernel32.dll"), "SleepEx");

            if (sleepAddress == IntPtr.Zero)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            IntPtr hThread = CreateRemoteThread(
                hProcess,
                IntPtr.Zero,
                0,
                sleepAddress,
                (IntPtr)(120000 | 0x80000000), // 2 minutes of delay execution state, you should inject within this time frame or the thread just goes away
                0, // Immediate execution
                IntPtr.Zero);

            if (hThread == IntPtr.Zero)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            var newThreadID = GetThreadId(hThread);
            Console.WriteLine("Process {0} now has Thread ID {1} ", processId, newThreadID);
            return hThread;
        }
    }
}
