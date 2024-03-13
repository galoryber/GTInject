using System;
using System.Text;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Management;
using Microsoft.Win32.SafeHandles;
using System.ComponentModel;
using static GTInject.SysCalls.WinNative;

namespace GTInject.AlertableThreads
{
    internal class Alertable
    {
        public static void GetThreads(bool filterUntrusted)
        {
            Process[] allProcs = Process.GetProcesses();
            for (int varProc = 0; varProc<allProcs.Length; varProc++)
            {
                StringBuilder ProcNThread = new StringBuilder();
                bool ThreadMatch = false;
                var procArch = "x64";
                bool is32 = false;
                try
                {
                    IsWow64Process(allProcs[varProc].Handle, out is32);
                }
                catch (Exception)
                {
                continue; // no access to process as current user, can't interact with it
                }
                if (is32) { procArch = "x86"; }
                var procIntegrity = GetProcessIntegrityLevel(allProcs[varProc].Id);
                if (filterUntrusted)
                {
                    if (procIntegrity == "Untrusted" || procIntegrity == "Low")
                    {
                        continue; //Don't display Untrusted integrity levels, this contains things like AppContainer integrity levels which are mostly unusable
                    }
                }

                string procUser = GetProcessOwner(allProcs[varProc].Id);
                ProcNThread.AppendFormat("[+] Process: {0,-6} | {1,-3} | {2,-18} | {3, -10} | {4,-35}", allProcs[varProc].Id, procArch, procUser, procIntegrity, allProcs[varProc].ProcessName);
                ProcNThread.Append(Environment.NewLine);

                var allThreads = allProcs[varProc].Threads;
                for (int varThread = 0; varThread < allThreads.Count; varThread++)
                {
                    if ((allThreads[varThread].ThreadState.ToString() == "Wait") && ((allThreads[varThread].WaitReason.ToString() == "Suspended") || (allThreads[varThread].WaitReason.ToString() == "ExecutionDelay")))
                    {
                        ThreadMatch = true;
                        ProcNThread.AppendFormat("        Thread: {0,-6}->{1,-15}", allThreads[varThread].Id, allThreads[varThread].WaitReason);
                        ProcNThread.Append(Environment.NewLine);
                    }
                }
                if (ThreadMatch)
                {
                    Console.WriteLine(ProcNThread);
                    ThreadMatch = false;
                }

            }
            return;
        }
        public static string GetProcessOwner(int processId)
        {
        string query = "Select Handle From Win32_Process Where ProcessID = " + processId;
        ManagementObjectSearcher searcher = new ManagementObjectSearcher(query);
        ManagementObjectCollection processList = searcher.Get();

        foreach (ManagementObject obj in processList)
        {
            string[] argList = new string[] { string.Empty, string.Empty };
            int returnVal = Convert.ToInt32(obj.InvokeMethod("GetOwner", argList));
            if (returnVal == 0)
            {
                // return DOMAIN\user
                return argList[1] + "\\" + argList[0];
            }
        }

        return "NO OWNER";
    }


        public class SafeTokenHandle : SafeHandleZeroOrMinusOneIsInvalid
        {
            private SafeTokenHandle() : base(true)
            {
            }

            internal SafeTokenHandle(IntPtr handle) : base(true)
            {
                base.SetHandle(handle);
            }

            [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            internal static extern bool CloseHandle(IntPtr handle);

            protected override bool ReleaseHandle()
            {
                return CloseHandle(base.handle);
            }
        }

        // I'm using this class just to house the imports for the native Windows API
        // functions to help keep the code organized apart from the custom functions
        // that I use within this program.
        public class NativeMethod
        {
            // Import the necessary Windows API functions
            [DllImport("advapi32", CharSet = CharSet.Auto, SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool OpenProcessToken(IntPtr hProcess, UInt32 desiredAccess, out SafeTokenHandle hToken);

            [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool GetTokenInformation(SafeTokenHandle hToken, TOKEN_INFORMATION_CLASS tokenInfoClass,
            IntPtr pTokenInfo, Int32 tokenInfoLength, out Int32 returnLength);

            [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            public static extern IntPtr GetSidSubAuthority(IntPtr pSid, UInt32 nSubAuthority);

            [DllImport("kernel32.dll")]
            public static extern bool IsWow64Process(IntPtr hProcess, out bool wow64Process);

            // Token Specific Access Rights
            public const UInt32 TOKEN_QUERY = 0x0008;

            // Set the error code returned from GetTokenInformation due to null buffer
            public const Int32 ERROR_INSUFFICIENT_BUFFER = 122;

            // Process integrity rid values
            public const Int32 SECURITY_MANDATORY_UNTRUSTED_RID = 0x00000000;
            public const Int32 SECURITY_MANDATORY_LOW_RID = 0x00001000;
            public const Int32 SECURITY_MANDATORY_MEDIUM_RID = 0x00002000;
            public const Int32 SECURITY_MANDATORY_HIGH_RID = 0x00003000;
            public const Int32 SECURITY_MANDATORY_SYSTEM_RID = 0x00004000;
        }

        public static string GetProcessIntegrityLevel(int pid)
        {
            int rid = -1;
            SafeTokenHandle hToken = null;
            int cbTokenIL = 0;
            IntPtr pTokenIL = IntPtr.Zero;
            string integrity = "";

            try
            {
                // Open the access token of the given process with TOKEN_QUERY by it's PID
                Process process = Process.GetProcessById(pid);
                IntPtr processHandle = process.Handle;

                bool success = NativeMethod.OpenProcessToken(processHandle, NativeMethod.TOKEN_QUERY, out hToken);
                if (!success)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                // Note that we expect GetTokenInformation to return false with
                // the ERROR_INSUFFICIENT_BUFFER error code because we've given it a null buffer
                if (!NativeMethod.GetTokenInformation(hToken,
                    TOKEN_INFORMATION_CLASS.TokenIntegrityLevel, IntPtr.Zero, 0,
                    out cbTokenIL))
                {
                    int error = Marshal.GetLastWin32Error();
                    if (error != NativeMethod.ERROR_INSUFFICIENT_BUFFER)
                    {
                        throw new Win32Exception(error);
                    }
                }

                // Now we allocate a buffer for the integrity level information.
                pTokenIL = Marshal.AllocHGlobal(cbTokenIL);
                if (pTokenIL == IntPtr.Zero)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                // Now we ask for the integrity level information again
                if (!NativeMethod.GetTokenInformation(hToken,
                    TOKEN_INFORMATION_CLASS.TokenIntegrityLevel, pTokenIL, cbTokenIL,
                    out cbTokenIL))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                // Marshal the TOKEN_MANDATORY_LABEL struct from native to .NET object.
                TOKEN_MANDATORY_LABEL tokenIL = (TOKEN_MANDATORY_LABEL)
                    Marshal.PtrToStructure(pTokenIL, typeof(TOKEN_MANDATORY_LABEL));

                IntPtr pIL = NativeMethod.GetSidSubAuthority(tokenIL.Label.Sid, 0);
                rid = Marshal.ReadInt32(pIL);

                //Console.WriteLine("rid : " + rid);
                // Identify the integrity lab from it's rid
                switch (rid)
                {
                    case NativeMethod.SECURITY_MANDATORY_UNTRUSTED_RID:
                        integrity = "Untrusted"; break;
                    case NativeMethod.SECURITY_MANDATORY_LOW_RID:
                        integrity = "Low"; break;
                    case NativeMethod.SECURITY_MANDATORY_MEDIUM_RID:
                        integrity = "Medium"; break;
                    case NativeMethod.SECURITY_MANDATORY_HIGH_RID:
                        integrity = "High"; break;
                    case NativeMethod.SECURITY_MANDATORY_SYSTEM_RID:
                        integrity = "System"; break;
                    default:
                        integrity = "Unknown"; break;
                }
            }
            catch (Exception ex)
            {
                if (ex.Message == "Access is denied")
                {
                    integrity = "Access Denied";
                }

                if (ex.Message == $"Cannot process request because the process ({pid}) has exited.")
                {
                    integrity = ex.Message;
                }
            }
            finally
            {
                // Clean up
                if (hToken != null)
                {
                    hToken.Close();
                    hToken = null;
                }
                if (pTokenIL != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(pTokenIL);
                    pTokenIL = IntPtr.Zero;
                    cbTokenIL = 0;
                }
            }
            return integrity;
        }
    }
}

//https://devblogs.microsoft.com/oldnewthing/20221017-00/?p=107291 
// possible info on getting integrity levels
//https://learn.microsoft.com/en-us/previous-versions/dotnet/articles/bb625963(v=msdn.10)#uiaccess-for-ui-automation-applications%20%20TITLE=
//correspondign values for integrity levels
// Easier, reuse other peoples genius -- https://github.com/gh0x0st/wanderer/blob/main/wanderer/wanderer/Program.cs