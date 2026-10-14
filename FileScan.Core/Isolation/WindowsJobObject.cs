using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace FileScan.Scanning;

/// <summary>
/// Job Object do Windows para UM worker: <c>KILL_ON_JOB_CLOSE</c> (o worker morre se o hospedeiro
/// morrer ou largar o handle), no máximo 1 processo ativo (o worker não cria processos), teto de memória
/// comprometida por processo e sem diálogo de erro (<c>DIE_ON_UNHANDLED_EXCEPTION</c>).
/// Falha ao aplicar lança: o chamador trata como worker não iniciável (NotInspected), nunca como Clean.
/// </summary>
internal sealed class WindowsJobObject : IDisposable
{
    private const int JobObjectExtendedLimitInformation = 9;
    private const uint LimitActiveProcess = 0x00000008;
    private const uint LimitProcessMemory = 0x00000100;
    private const uint LimitDieOnUnhandledException = 0x00000400;
    private const uint LimitKillOnJobClose = 0x00002000;

    private nint _handle;

    private WindowsJobObject(nint handle) => _handle = handle;

    public static bool IsSupported => OperatingSystem.IsWindows();

    /// <summary>Cria o job, aplica os limites e associa o processo. Lança <see cref="Win32Exception"/> em falha.</summary>
    public static WindowsJobObject Create(Process process, long processMemoryLimitBytes)
    {
        nint handle = CreateJobObject(0, null);
        if (handle == 0) throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateJobObject");

        var job = new WindowsJobObject(handle);
        try
        {
            var info = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
            info.BasicLimitInformation.LimitFlags =
                LimitKillOnJobClose | LimitActiveProcess | LimitDieOnUnhandledException;
            info.BasicLimitInformation.ActiveProcessLimit = 1;
            if (processMemoryLimitBytes > 0)
            {
                info.BasicLimitInformation.LimitFlags |= LimitProcessMemory;
                info.ProcessMemoryLimit = (nuint)processMemoryLimitBytes;
            }

            int size = Marshal.SizeOf<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>();
            nint buffer = Marshal.AllocHGlobal(size);
            try
            {
                Marshal.StructureToPtr(info, buffer, false);
                if (!SetInformationJobObject(handle, JobObjectExtendedLimitInformation, buffer, (uint)size))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "SetInformationJobObject");
            }
            finally { Marshal.FreeHGlobal(buffer); }

            if (!AssignProcessToJobObject(handle, process.Handle))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "AssignProcessToJobObject");

            return job;
        }
        catch
        {
            job.Dispose();
            throw;
        }
    }

    /// <summary>Fechar o handle mata o worker (KILL_ON_JOB_CLOSE).</summary>
    public void Dispose()
    {
        nint handle = Interlocked.Exchange(ref _handle, 0);
        if (handle != 0) CloseHandle(handle);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_BASIC_LIMIT_INFORMATION
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public nuint MinimumWorkingSetSize;
        public nuint MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public nuint Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IO_COUNTERS
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
    {
        public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
        public IO_COUNTERS IoInfo;
        public nuint ProcessMemoryLimit;
        public nuint JobMemoryLimit;
        public nuint PeakProcessMemoryUsed;
        public nuint PeakJobMemoryUsed;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern nint CreateJobObject(nint attributes, string? name);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetInformationJobObject(nint job, int infoClass, nint info, uint size);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AssignProcessToJobObject(nint job, nint process);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(nint handle);
}
