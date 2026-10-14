using System.Diagnostics;
using System.Runtime.InteropServices;

namespace FileScan.Scanning;

/// <summary>Como iniciar o worker: o host <c>dotnet</c> + o <c>FileScan.Worker.dll</c>.</summary>
internal sealed record WorkerLaunch(string HostPath, string WorkerDll,
    Func<System.Diagnostics.Process, long, IDisposable?>? LimitApplier = null)
{
    public string Key => HostPath + "|" + WorkerDll;
}

/// <summary>
/// Localiza o worker SEM fallback: ausente ou inconsistente = erro de configuração explícito (o chamador
/// devolve NotInspected e loga), nunca execução em processo.
/// </summary>
internal static class WorkerLocator
{
    public const string DirectoryName = "filescan-worker";
    public const string FileName = "FileScan.Worker.dll";

    /// <returns>Launch válido ou, em <paramref name="error"/>, o porquê de não haver.</returns>
    public static WorkerLaunch? Resolve(string? explicitPath, out string? error)
    {
        string? dll = ResolveWorkerDll(explicitPath, out error);
        if (dll is null) return null;

        string? host = ResolveHost();
        if (host is null)
        {
            error = "o host 'dotnet' não foi encontrado (aplicação self-contained/single-file sem runtime instalado?). " +
                    "O FileScan.Worker é framework-dependent e precisa do runtime .NET 10 no servidor; defina DOTNET_HOST_PATH ou instale o runtime.";
            return null;
        }

        var versionProblem = CheckVersion(dll);
        if (versionProblem is not null)
        {
            error = versionProblem;
            return null;
        }

        error = null;
        return new WorkerLaunch(host, dll);
    }

    private static string? ResolveWorkerDll(string? explicitPath, out string? error)
    {
        string dll;
        if (!string.IsNullOrWhiteSpace(explicitPath))
        {
            dll = Path.GetFullPath(explicitPath);
        }
        else
        {
            string baseDir = Path.GetDirectoryName(typeof(WorkerLocator).Assembly.Location) is { Length: > 0 } located
                ? located
                : AppContext.BaseDirectory;
            dll = Path.Combine(baseDir, DirectoryName, FileName);
        }

        if (!File.Exists(dll))
        {
            error = $"FileScan.Worker não encontrado em '{dll}'. Isolation=Worker (default) exige o worker empacotado " +
                    $"com o FileScan.Core (pasta '{DirectoryName}' ao lado do FileScan.Core.dll, inclusive no publish). " +
                    "Não há fallback para InProcess: defina FileScannerOptions.WorkerPath ou corrija o empacotamento.";
            return null;
        }

        string stem = dll[..^".dll".Length];
        foreach (var companion in new[] { stem + ".runtimeconfig.json", stem + ".deps.json" })
        {
            if (!File.Exists(companion))
            {
                error = $"FileScan.Worker incompleto: falta '{Path.GetFileName(companion)}' ao lado de '{dll}'.";
                return null;
            }
        }

        error = null;
        return dll;
    }

    private static string? ResolveHost()
    {
        string executable = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "dotnet.exe" : "dotnet";

        string? env = Environment.GetEnvironmentVariable("DOTNET_HOST_PATH");
        if (!string.IsNullOrWhiteSpace(env) && File.Exists(env)) return env;

        string? current = Environment.ProcessPath;
        if (current is not null &&
            string.Equals(Path.GetFileName(current), executable, StringComparison.OrdinalIgnoreCase) &&
            File.Exists(current))
            return current;

        // .../dotnet/shared/Microsoft.NETCore.App/<versão>/  =>  .../dotnet/dotnet
        try
        {
            var runtimeDirectory = new DirectoryInfo(
                System.Runtime.InteropServices.RuntimeEnvironment.GetRuntimeDirectory().TrimEnd(Path.DirectorySeparatorChar));
            var root = runtimeDirectory.Parent?.Parent?.Parent;
            if (root is not null)
            {
                string candidate = Path.Combine(root.FullName, executable);
                if (File.Exists(candidate)) return candidate;
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            // cai para o DOTNET_ROOT
        }

        string? dotnetRoot = Environment.GetEnvironmentVariable("DOTNET_ROOT");
        if (!string.IsNullOrWhiteSpace(dotnetRoot))
        {
            string candidate = Path.Combine(dotnetRoot, executable);
            if (File.Exists(candidate)) return candidate;
        }

        return null;
    }

    /// <summary>Worker de outra versão que o Core não protege contra protocolo/semântica divergentes.</summary>
    private static string? CheckVersion(string workerDll)
    {
        try
        {
            string? worker = FileVersionInfo.GetVersionInfo(workerDll).FileVersion;
            string? core = FileVersionInfo.GetVersionInfo(typeof(WorkerLocator).Assembly.Location).FileVersion;
            if (!string.IsNullOrEmpty(core) && !string.IsNullOrEmpty(worker) && core != worker)
                return $"FileScan.Worker ({worker}) e FileScan.Core ({core}) têm versões diferentes; reempacote os dois juntos.";
        }
        catch (Exception ex) when (ex is IOException or ArgumentException or UnauthorizedAccessException)
        {
            // sem Assembly.Location (single-file): a checagem de protocolo no handshake cobre.
        }

        return null;
    }
}
