using System.Diagnostics;
using FileScan.Scanning;
using Xunit;
using Xunit.Sdk;

namespace FileScan.Tests.Isolation;

/// <summary>
/// Infra dos testes do isolamento em worker. Cada teste usa um POOL PRÓPRIO (a chave do pool inclui
/// <c>WorkerRecycleAfterScans</c>, que aqui é único por chamada), para que os contadores de reinício/morte sejam
/// determinísticos mesmo com testes rodando em paralelo. Timeouts são generosos (outras sessões rodam builds
/// pesados na máquina) e as falhas por TRAVAMENTO do teste têm mensagem distinta das falhas de asserção.
/// </summary>
internal static class IsolationHarness
{
    private static int _sequence = 100;

    /// <summary>Teto para qualquer chamada ao serviço sob teste: acima disso é o TESTE que travou, não a asserção.</summary>
    public static readonly TimeSpan Hang = TimeSpan.FromSeconds(120);

    /// <summary>Caminho do worker FALSO (FileScan.Tests.Child sem argumentos): o WorkerHost real + sabotagem por prefixo.</summary>
    public static string FakeWorkerPath()
    {
        var tfm = new DirectoryInfo(AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar));
        var configuration = tfm.Parent!;
        var repository = configuration.Parent!.Parent!.Parent!;
        return Path.Combine(repository.FullName, "FileScan.Tests.Child", "bin", configuration.Name, tfm.Name,
            "FileScan.Tests.Child.dll");
    }

    public static FileScannerOptions Options(bool fakeWorker, Action<FileScannerOptions>? tweak = null,
        List<string>? events = null)
    {
        var options = new FileScannerOptions
        {
            AllowedExtensions = ["pdf"],
            WorkerTimeout = TimeSpan.FromSeconds(60),
            WorkerPoolSize = 1,
            WorkerRecycleAfterScans = Interlocked.Increment(ref _sequence),
        };
        if (fakeWorker)
        {
            string path = FakeWorkerPath();
            Assert.True(File.Exists(path), $"worker falso não encontrado: {path}");
            options.WorkerPath = path;
        }

        if (events is not null)
            options.OnIsolationEvent = message => { lock (events) events.Add(message); };
        tweak?.Invoke(options);
        return options;
    }

    public static async Task<T> Bounded<T>(Task<T> task, string what)
    {
        try
        {
            return await task.WaitAsync(Hang);
        }
        catch (TimeoutException)
        {
            throw new XunitException($"TRAVOU: '{what}' não terminou em {Hang.TotalSeconds}s — o serviço sob teste não aplicou timeout/cancelamento (não é falha de asserção de veredito).");
        }
    }

    public static Task<ScanResponse> Scan(FileScanService service, string fileName, byte[] bytes,
        CancellationToken ct = default) => Bounded(service.ScanAsync(fileName, bytes, ct), fileName);

    public static WorkerPool PoolOf(FileScanService service) =>
        service.Isolated?.Pool ?? throw new XunitException("o serviço ainda não criou um pool (nenhum scan chegou ao worker)");

    public static void AssertVerdict(ScanVerdict expected, ScanResponse actual, string context)
    {
        if (actual.Verdict != expected)
            throw new XunitException(
                $"{context}: esperado {expected}, obtido {actual.Verdict} (Reason: {actual.Reason})");
    }

    /// <summary>PID existe e ainda não saiu? (só para PIDs que o pool do TESTE criou).</summary>
    public static bool IsAlive(int pid)
    {
        try
        {
            using var process = Process.GetProcessById(pid);
            return !process.HasExited;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    public static async Task<bool> WaitUntil(Func<bool> condition, TimeSpan limit)
    {
        var stopwatch = Stopwatch.StartNew();
        while (stopwatch.Elapsed < limit)
        {
            if (condition()) return true;
            await Task.Delay(100);
        }

        return condition();
    }
}
