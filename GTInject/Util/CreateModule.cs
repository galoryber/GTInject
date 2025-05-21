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

        public static PROCESS_INFORMATION CreateSuspendedProcess(string applicationPath)
        {
            STARTUPINFO startupInfo = new STARTUPINFO();
            PROCESS_INFORMATION processInfo = new PROCESS_INFORMATION();

            if (!CreateProcess(
                applicationPath,
                null,
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

            return hThread;
        }
        
        // TODO: If possible, create other wait state threads - like DeleyExecution state threads
        // DelayExecution is what it sounds like - basiclaly just means something is sleeping for a time. 
        // Create thread with thread flags "immediate exectuion" but have the start address resolve to kernel32!Sleep for a defined time
        // Thread should start and be waiting

    }
}
