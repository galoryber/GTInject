using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Management;

namespace GTInject.AlertableThreads
{
    internal class Alertable
    {
        public static void GetThreads()
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
                string procUser = GetProcessOwner(allProcs[varProc].Id);
                ProcNThread.AppendFormat("[+] Process: {0,-6} | {1,-3} | {2,-20} | {3,-35}", allProcs[varProc].Id, procArch, procUser, allProcs[varProc].ProcessName);
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

    [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.Winapi)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool IsWow64Process([In] IntPtr processHandle,
    [Out, MarshalAs(UnmanagedType.Bool)] out bool wow64Process);
    }
}
