using FileScan.Scanning;
using Xunit;
using static FileScan.Tests.Isolation.IsolationHarness;

namespace FileScan.Tests.Isolation;

/// <summary>
/// Invariantes do <c>ContentOutcome</c> (uma regra por prefixo do worker falso), Job Object lido de volta do SO,
/// worker morto que não volta ao pool, sanitização do log e Reason sem caminhos do servidor.
/// </summary>
public class IsolationInvariantTests
{
    [Theory]
    [InlineData("badincomplete-", ActiveContentAction.Reject)]  // integral x motivo de incompletude
    [InlineData("badwarnings-", ActiveContentAction.Flag)]      // conteúdo ativo x warnings
    [InlineData("noreason-", ActiveContentAction.Reject)]       // terminal Rejected sem motivo
    [InlineData("ignorefull-", ActiveContentAction.Ignore)]     // sob Ignore a inspeção nunca é integral
    [InlineData("rejectactive-", ActiveContentAction.Reject)]   // sob Reject "ativo detectado" não existe
    [InlineData("flagterminal-", ActiveContentAction.Flag)]     // terminal Rejected só existe sob Reject
    public async Task IncoherentButWellFormedAnswer_IsAnIsolationFailure_AndKillsTheWorker(string prefix, ActiveContentAction policy)
    {
        var service = new FileScanService(Options(fakeWorker: true, o => o.OnActiveContent = policy));
        // controle: o worker falso honesto responde normalmente sob esta política (Ignore nunca é Clean)
        var control = await Scan(service, "antes.pdf", Samples.CleanPdf());
        Assert.NotEqual(ScanVerdict.Rejected, control.Verdict);
        var pool = PoolOf(service);
        int pidBefore = Assert.Single(pool.LivePids);

        var response = await Scan(service, prefix + "x.pdf", Samples.CleanPdf());

        Assert.True(pool.KilledCount == 1,
            $"'{prefix}' sob {policy} foi ACEITO pelo hospedeiro (KilledCount={pool.KilledCount}, veredito {response.Verdict})");
        AssertVerdict(ScanVerdict.NotInspected, response, $"'{prefix}' sob {policy}");
        Assert.Contains("inspeção isolada não concluída", response.Reason);
        Assert.False(IsAlive(pidBefore));
    }

    [Fact]
    public async Task OnWindows_TheJobObjectReallyCarriesTheDocumentedLimits()
    {
        if (!OperatingSystem.IsWindows()) return;

        long cap = 512L * 1024 * 1024;
        var service = new FileScanService(Options(fakeWorker: false, o => o.WorkerMaxMemoryBytes = cap));
        AssertVerdict(ScanVerdict.Clean, await Scan(service, "ok.pdf", Samples.CleanPdf()), "aquecimento");
        var worker = Assert.Single(PoolOf(service).LiveWorkers);

        var limits = worker.QueryJobLimits(); // lido de volta do SO (QueryInformationJobObject), não do nosso código
        Assert.NotNull(limits);
        Assert.True((limits!.LimitFlags & WindowsJobObject.KillOnJobCloseFlag) != 0, "falta KILL_ON_JOB_CLOSE");
        Assert.True((limits.LimitFlags & WindowsJobObject.ActiveProcessFlag) != 0 && limits.ActiveProcessLimit == 1,
            "falta o limite de 1 processo");
        Assert.True((limits.LimitFlags & WindowsJobObject.ProcessMemoryFlag) != 0, "falta o teto de memória");
        Assert.Equal((ulong)(cap + 128L * 1024 * 1024), limits.ProcessMemoryLimit);
        Assert.True((limits.LimitFlags & WindowsJobObject.DieOnUnhandledExceptionFlag) != 0, "falta DIE_ON_UNHANDLED_EXCEPTION");
    }

    [Fact]
    public async Task KilledWorker_NeverGoesBackToTheIdlePool()
    {
        var service = new FileScanService(Options(fakeWorker: true));
        AssertVerdict(ScanVerdict.Clean, await Scan(service, "1.pdf", Samples.CleanPdf()), "1º scan");
        var pool = PoolOf(service);
        var worker = Assert.Single(pool.LiveWorkers);
        Assert.False(worker.IsKilled);
        worker.Kill();
        Assert.True(worker.IsKilled);
        Assert.True(await WaitUntil(() => worker.HasExited, TimeSpan.FromSeconds(20)));
        AssertVerdict(ScanVerdict.Clean, await Scan(service, "2.pdf", Samples.CleanPdf()), "scan depois do Kill");
        Assert.NotEqual(worker.Pid, Assert.Single(pool.LivePids));
    }

    [Fact]
    public void IsolationLogSanitizer_NeutralizesUnicodeLineAndBidiCharacters()
    {
        char[] dangerous = [(char)0x2028, (char)0x2029, (char)0x202E, (char)0x200B, (char)0x0085, '\r', '\n'];
        string hostile = "a" + string.Concat(dangerous.Select(c => c + "x"));
        string clean = IsolatedFileScanService.Sanitize(hostile);
        foreach (char c in dangerous)
            Assert.DoesNotContain(c, clean);
        Assert.Equal("a" + string.Concat(dangerous.Select(_ => " x")), clean);
    }

    [Fact]
    public async Task ClientFacingReason_DoesNotLeakServerPaths_ButTheEventDoes()
    {
        string secretDirectory = Path.Combine(Path.GetTempPath(), "segredo-do-servidor");
        var events = new List<string>();
        var missing = new FileScanService(Options(false, o => o.WorkerPath = Path.Combine(secretDirectory, "FileScan.Worker.dll"), events));
        var response = await Scan(missing, "ok.pdf", Samples.CleanPdf());
        Assert.DoesNotContain("segredo-do-servidor", response.Reason);
        Assert.Contains(events, e => e.Contains("segredo-do-servidor"));

        // worker que não inicia (o host recebe um .dll que não é assembly): idem
        var dir = Directory.CreateTempSubdirectory("segredo-do-servidor-bad-").FullName;
        try
        {
            File.WriteAllText(Path.Combine(dir, "FileScan.Worker.dll"), "x");
            File.WriteAllText(Path.Combine(dir, "FileScan.Worker.runtimeconfig.json"), "{}");
            File.WriteAllText(Path.Combine(dir, "FileScan.Worker.deps.json"), "{}");
            var events2 = new List<string>();
            var bad = new FileScanService(Options(false, o => o.WorkerPath = Path.Combine(dir, "FileScan.Worker.dll"), events2));
            var response2 = await Scan(bad, "ok.pdf", Samples.CleanPdf());
            AssertVerdict(ScanVerdict.NotInspected, response2, "worker que não inicia");
            Assert.DoesNotContain("segredo-do-servidor", response2.Reason);
            Assert.DoesNotContain(dir, response2.Reason);
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch (IOException) { }
        }
    }
}
