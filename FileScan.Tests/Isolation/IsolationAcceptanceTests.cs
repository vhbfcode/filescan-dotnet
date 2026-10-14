using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.InteropServices;
using FileScan.Scanning;
using Xunit;
using static FileScan.Tests.Isolation.IsolationHarness;

namespace FileScan.Tests.Isolation;

/// <summary>
/// Aceitação do FileScan.Worker (0.4.0): o <c>PdfDocument.Open</c> roda em processo filho; nada que o filho faça
/// (estouro de pilha, OOM, travar, responder lixo, morrer) vira <c>Clean</c> nem derruba o processo de teste.
/// Os testes de ATAQUE usam o worker REAL (default de produção); os de FALHA usam o worker FALSO
/// (<c>FileScan.Tests.Child</c> sem argumentos), que roda o <c>WorkerHost</c> verdadeiro e sabota por prefixo do nome.
/// </summary>
public class IsolationAcceptanceTests
{
    // ------------------------------------------------------------------ ataques que a guarda pré-Open JÁ pega

    [Fact]
    public async Task GuardedAttacks_ThroughTheRealWorker_AreNotInspected_AndTheWorkerKeepsServing()
    {
        var service = new FileScanService(Options(fakeWorker: false));
        var attacks = new List<(string Name, byte[] Bytes)>();

        foreach (var (label, apply) in new (string, Func<string, string>)[]
                 {
                     ("id", t => t),
                     ("kids", t => t.Replace("/Kids", "/K#69ds")),
                     ("tudo", t => t.Replace("/Kids", "/K#69ds").Replace("/Names", "/N#61mes").Replace("/Dests", "/D#65sts")
                         .Replace("/Type", "/T#79pe").Replace("/Pages", "/P#61ges").Replace("/Parent", "/Par#65nt")),
                 })
        {
            Samples.BodyTransform = apply;
            try { GuardAttackCorpus.Register((name, make) => attacks.Add(($"{name}__{label}", make()))); }
            finally { Samples.BodyTransform = null; }
        }

        Assert.True(attacks.Count >= 90, $"corpus de ataques menor que o esperado ({attacks.Count})");

        var wrong = new List<string>();
        foreach (var (name, bytes) in attacks)
        {
            var response = await Scan(service, "ataque.pdf", bytes);
            if (response.Verdict != ScanVerdict.NotInspected)
                wrong.Add($"{name}: {response.Verdict} ({response.Reason})");
        }

        Assert.True(wrong.Count == 0, "ataques com veredito diferente de NotInspected:\n" + string.Join("\n", wrong));

        // o worker NÃO caiu (a guarda recusou antes do Open) e segue servindo; um PDF legítimo continua Clean.
        var pool = PoolOf(service);
        Assert.Equal(0, pool.KilledCount);
        AssertVerdict(ScanVerdict.Clean, await Scan(service, "ok.pdf", Samples.CleanPdf()), "PDF legítimo depois dos ataques");
    }

    // ------------------------------------------------------------------ ataques que PASSAM pela guarda e estouram o Open

    [Theory]
    [InlineData("dests_cadeia50000")]
    [InlineData("paginas20000")]
    [InlineData("paginas200000")]
    [InlineData("dests_ciclo2")]
    [InlineData("info_autoalias")]
    public async Task AttackPastTheGuard_OverflowsTheStack_NotInspected_HostSurvives_WorkerRestarts(string attack)
    {
        // 20 mil níveis estouram a pilha de 1 MB do Windows, mas NÃO a de 8 MB do Linux (o PdfPig abre o arquivo e
        // o resultado é Clean). Só 200 mil níveis estouram nos dois; este caso é exclusivo do Windows.
        if (attack == "paginas20000" && !OperatingSystem.IsWindows()) return;

        // "noguard-" liga o ponto interno que DESLIGA a guarda pré-Open no worker falso: o ataque chega ao
        // PdfDocument.Open do PdfPig 0.1.16 e estoura a pilha DO WORKER (exit code 0xC00000FD no Windows).
        var events = new List<string>();
        var service = new FileScanService(Options(fakeWorker: true, events: events));
        byte[] bytes = attack switch
        {
            "dests_cadeia50000" => Samples.PdfWithDests(50_000),
            "paginas20000" => Samples.PdfWithDeepPageTree(20_000),
            "paginas200000" => Samples.PdfWithDeepPageTree(200_000),
            "dests_ciclo2" => Samples.PdfWithDests(2, cycle: true),
            "info_autoalias" => Samples.PdfWithInfoValueSelfAlias(),
            _ => throw new ArgumentOutOfRangeException(nameof(attack)),
        };

        // primeiro um scan normal: fixa o worker "antes"
        AssertVerdict(ScanVerdict.Clean, await Scan(service, "antes.pdf", Samples.CleanPdf()), "controle antes do ataque");
        var pool = PoolOf(service);
        int pidBefore = Assert.Single(pool.LivePids);

        var response = await Scan(service, "noguard-" + attack + ".pdf", bytes);

        // PRIMEIRO a prova de que o worker realmente caiu: sem isso um "Clean" por pilha grande demais é confundido com falha de veredito.
        Assert.True(pool.KilledCount == 1, $"o ataque '{attack}' NÃO derrubou o worker (KilledCount={pool.KilledCount}; veredito {response.Verdict}): o ataque não estoura a pilha neste SO");
        AssertVerdict(ScanVerdict.NotInspected, response, "ataque que passa pela guarda");
        Assert.Contains("inspeção isolada não concluída", response.Reason);
        Assert.Equal(1, pool.KilledCount);
        Assert.False(IsAlive(pidBefore), "o worker que estourou a pilha deveria ter sido morto");
        Assert.Contains(events, e => e.Contains("falha de isolamento"));

        // o processo (este teste) está vivo, o worker REINICIA e o scan seguinte funciona — com outro PID
        AssertVerdict(ScanVerdict.Clean, await Scan(service, "depois.pdf", Samples.CleanPdf()), "controle depois do ataque");
        int pidAfter = Assert.Single(pool.LivePids);
        Assert.NotEqual(pidBefore, pidAfter);
        Assert.Equal(2, pool.StartedCount);
    }

    // ------------------------------------------------------------------ falhas do worker => NotInspected, nunca Clean

    [Theory]
    [InlineData("die-")]        // morre no meio do scan (Environment.Exit)
    [InlineData("garbage-")]    // escreve bytes que não são um quadro do protocolo
    [InlineData("badjson-")]    // quadro bem formado com JSON inválido
    [InlineData("truncated-")]  // anuncia 5000 bytes, entrega 10 e morre (fluxo truncado)
    [InlineData("liar-")]       // resposta bem formada que MENTE (veredito terminal Clean)
    [InlineData("wrongsize-")]  // resposta bem formada com tamanho diferente do enviado
    [InlineData("throw-")]      // exceção inesperada dentro do worker
    public async Task WorkerFailure_IsNotInspected_NeverClean_AndTheWorkerIsReplaced(string prefix)
    {
        var events = new List<string>();
        var service = new FileScanService(Options(fakeWorker: true, events: events));

        AssertVerdict(ScanVerdict.Clean, await Scan(service, "antes.pdf", Samples.CleanPdf()), "controle antes");
        var pool = PoolOf(service);
        int pidBefore = Assert.Single(pool.LivePids);

        var response = await Scan(service, prefix + "x.pdf", Samples.CleanPdf()); // conteúdo LIMPO: só o worker falha

        AssertVerdict(ScanVerdict.NotInspected, response, $"falha '{prefix}'");
        Assert.NotEqual(ScanVerdict.Clean, response.Verdict);
        Assert.Contains("inspeção isolada não concluída", response.Reason);
        Assert.Equal(1, pool.KilledCount);
        Assert.False(IsAlive(pidBefore), "worker com falha deveria ter sido morto");
        Assert.NotEmpty(events);

        AssertVerdict(ScanVerdict.Clean, await Scan(service, "depois.pdf", Samples.CleanPdf()), "controle depois");
        Assert.NotEqual(pidBefore, Assert.Single(pool.LivePids));
    }

    [Fact]
    public async Task Timeout_KillsTheWorker_NotInspected_AndTheNextScanWorks()
    {
        var service = new FileScanService(Options(fakeWorker: true, o => o.WorkerTimeout = TimeSpan.FromSeconds(4)));
        AssertVerdict(ScanVerdict.Clean, await Scan(service, "antes.pdf", Samples.CleanPdf()), "aquecimento");
        var pool = PoolOf(service);
        int hungPid = Assert.Single(pool.LivePids);

        var stopwatch = Stopwatch.StartNew();
        var response = await Scan(service, "hang-x.pdf", Samples.CleanPdf());
        stopwatch.Stop();

        AssertVerdict(ScanVerdict.NotInspected, response, "worker travado");
        Assert.Contains("timeout", response.Reason);
        Assert.True(stopwatch.Elapsed >= TimeSpan.FromSeconds(3.5), $"o timeout disparou cedo demais ({stopwatch.Elapsed})");
        Assert.True(stopwatch.Elapsed < TimeSpan.FromSeconds(60), $"o timeout demorou demais ({stopwatch.Elapsed})");
        Assert.True(await WaitUntil(() => !IsAlive(hungPid), TimeSpan.FromSeconds(20)), "o worker travado deveria ter sido morto");

        AssertVerdict(ScanVerdict.Clean, await Scan(service, "depois.pdf", Samples.CleanPdf()), "scan depois do timeout");
        Assert.Equal(2, pool.StartedCount);
    }

    [Fact]
    public async Task SlowButWithinTheTimeout_StillCompletes()
    {
        var service = new FileScanService(Options(fakeWorker: true, o => o.WorkerTimeout = TimeSpan.FromSeconds(30)));
        var response = await Scan(service, "slow-1500-x.pdf", Samples.CleanPdf());
        AssertVerdict(ScanVerdict.Clean, response, "scan lento, mas dentro do prazo");
        Assert.Equal(0, PoolOf(service).KilledCount);
    }

    [Fact]
    public async Task WorkerKilledBetweenScans_IsDetected_AndReplaced()
    {
        var service = new FileScanService(Options(fakeWorker: true));
        AssertVerdict(ScanVerdict.Clean, await Scan(service, "1.pdf", Samples.CleanPdf()), "1º scan");
        var pool = PoolOf(service);
        int pid = Assert.Single(pool.LivePids);

        using (var victim = Process.GetProcessById(pid)) // PID que o pool DESTE teste criou
        {
            victim.Kill(entireProcessTree: true);
            victim.WaitForExit(10_000);
        }

        AssertVerdict(ScanVerdict.Clean, await Scan(service, "2.pdf", Samples.CleanPdf()), "scan depois de o worker morrer ocioso");
        Assert.NotEqual(pid, Assert.Single(pool.LivePids));
        Assert.Equal(2, pool.StartedCount);
    }

    [Fact]
    public async Task Worker_IsRecycledAfterNScans()
    {
        var service = new FileScanService(Options(fakeWorker: true, o => o.WorkerRecycleAfterScans = 3));
        // a chave do pool inclui o N de reciclagem; 3 repete entre testes, então este usa um pool dedicado via pool size
        var seen = new HashSet<int>();
        for (int i = 0; i < 7; i++)
        {
            AssertVerdict(ScanVerdict.Clean, await Scan(service, $"{i}.pdf", Samples.CleanPdf()), $"scan {i}");
            var pool = PoolOf(service);
            foreach (var pid in pool.LivePids) seen.Add(pid);
        }

        var finalPool = PoolOf(service);
        Assert.True(finalPool.RetiredCount >= 2, $"esperava >= 2 reciclagens em 7 scans com N=3; houve {finalPool.RetiredCount}");
        Assert.True(seen.Count >= 3, $"esperava >= 3 workers distintos em 7 scans com N=3; houve {seen.Count}");
    }

    // ------------------------------------------------------------------ cancelamento e concorrência

    [Fact]
    public async Task Cancellation_IsPropagated_AndKillsTheWorker()
    {
        var service = new FileScanService(Options(fakeWorker: true, o => o.WorkerTimeout = TimeSpan.FromMinutes(5)));
        AssertVerdict(ScanVerdict.Clean, await Scan(service, "antes.pdf", Samples.CleanPdf()), "aquecimento");
        var pool = PoolOf(service);
        int pid = Assert.Single(pool.LivePids);

        using var cts = new CancellationTokenSource();
        var pending = service.ScanAsync("hang-x.pdf", Samples.CleanPdf(), cts.Token);
        await Task.Delay(1500);
        Assert.False(pending.IsCompleted, "o scan deveria estar preso no worker travado");
        await cts.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Bounded(pending, "cancelamento"));
        Assert.True(await WaitUntil(() => !IsAlive(pid), TimeSpan.FromSeconds(20)), "o worker deveria ter sido morto no cancelamento");

        AssertVerdict(ScanVerdict.Clean, await Scan(service, "depois.pdf", Samples.CleanPdf()), "scan depois do cancelamento");
    }

    [Fact]
    public async Task AlreadyCancelledToken_ThrowsWithoutStartingAWorker()
    {
        var service = new FileScanService(Options(fakeWorker: true));
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => service.ScanAsync("x.pdf", Samples.CleanPdf(), cts.Token));
        Assert.Null(service.Isolated!.Pool);
    }

    [Fact]
    public async Task ConcurrentScans_AreSafe_AndBoundedByThePoolSize()
    {
        var service = new FileScanService(Options(fakeWorker: false, o => o.WorkerPoolSize = 2));
        byte[] clean = Samples.CleanPdf();
        byte[] js = Samples.PdfWithJavaScript();
        byte[] hostile = Samples.PdfWithDests(2, cycle: true);

        var tasks = Enumerable.Range(0, 24).Select(i => (i % 3) switch
        {
            0 => (Expected: ScanVerdict.Clean, Task: Scan(service, "c.pdf", clean)),
            1 => (Expected: ScanVerdict.Rejected, Task: Scan(service, "j.pdf", js)),
            _ => (Expected: ScanVerdict.NotInspected, Task: Scan(service, "h.pdf", hostile)),
        }).ToList();

        await Bounded(Task.WhenAll(tasks.Select(t => t.Task)), "24 scans concorrentes");
        for (int i = 0; i < tasks.Count; i++)
            AssertVerdict(tasks[i].Expected, await tasks[i].Task, $"scan concorrente #{i}");

        var pool = PoolOf(service);
        Assert.True(pool.StartedCount <= 2, $"o pool de 2 iniciou {pool.StartedCount} workers");
        Assert.True(pool.LivePids.Length <= 2);
    }

    [Fact]
    public async Task ConcurrentFailures_DoNotPoisonTheOtherScans()
    {
        var service = new FileScanService(Options(fakeWorker: true, o =>
        {
            o.WorkerPoolSize = 3;
            o.WorkerTimeout = TimeSpan.FromSeconds(30);
        }));
        var scans = Enumerable.Range(0, 18).Select(i => i % 3 == 0
            ? (Name: "die-" + i + ".pdf", Expected: ScanVerdict.NotInspected)
            : (Name: i + ".pdf", Expected: ScanVerdict.Clean)).ToList();

        var tasks = scans.Select(s => Scan(service, s.Name, Samples.CleanPdf())).ToList();
        await Bounded(Task.WhenAll(tasks), "scans concorrentes com falhas");
        for (int i = 0; i < scans.Count; i++)
            AssertVerdict(scans[i].Expected, await tasks[i], scans[i].Name);
    }

    // ------------------------------------------------------------------ configuração: nunca fallback silencioso

    [Fact]
    public async Task MissingWorker_IsNotInspected_WithAClearLoggedConfigurationError_NeverClean_NeverInProcess()
    {
        var events = new List<string>();
        var service = new FileScanService(Options(fakeWorker: false, o =>
            o.WorkerPath = Path.Combine(Path.GetTempPath(), "filescan-nao-existe", "FileScan.Worker.dll"), events));

        // um PDF que em InProcess seria Clean: se houvesse fallback silencioso, sairia Clean.
        var response = await Scan(service, "ok.pdf", Samples.CleanPdf());

        AssertVerdict(ScanVerdict.NotInspected, response, "worker ausente");
        Assert.Contains("erro de configuração", response.Reason);
        Assert.DoesNotContain("filescan-nao-existe", response.Reason); // o Reason vai ao cliente da API: sem caminhos do servidor
        Assert.Contains(events, e => e.Contains("FileScan.Worker não encontrado") && e.Contains("filescan-nao-existe"));
        Assert.Contains(events, e => e.Contains("erro de configuração do isolamento"));
        Assert.Null(service.Isolated!.Pool); // nem tentou iniciar processo
    }

    [Fact]
    public async Task UnstartableWorker_IsNotInspected_NeverClean()
    {
        // existe, tem runtimeconfig/deps, mas NÃO é um worker: sai sem handshake.
        var dir = Directory.CreateTempSubdirectory("filescan-badworker-").FullName;
        try
        {
            File.WriteAllText(Path.Combine(dir, "FileScan.Worker.dll"), "isto não é um assembly");
            File.WriteAllText(Path.Combine(dir, "FileScan.Worker.runtimeconfig.json"), "{}");
            File.WriteAllText(Path.Combine(dir, "FileScan.Worker.deps.json"), "{}");

            var events = new List<string>();
            var service = new FileScanService(Options(fakeWorker: false, o =>
                o.WorkerPath = Path.Combine(dir, "FileScan.Worker.dll"), events));

            var response = await Scan(service, "ok.pdf", Samples.CleanPdf());

            AssertVerdict(ScanVerdict.NotInspected, response, "worker que não inicia");
            Assert.NotEqual(ScanVerdict.Clean, response.Verdict);
            Assert.NotEmpty(events);
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch (IOException) { }
        }
    }

    [Fact]
    public async Task InProcess_DoesNotNeedAWorker_AndIsOptIn()
    {
        Assert.Equal(IsolationMode.Worker, new FileScannerOptions().Isolation); // default seguro
        var service = new FileScanService(Options(fakeWorker: false, o =>
        {
            o.Isolation = IsolationMode.InProcess;
            o.WorkerPath = Path.Combine(Path.GetTempPath(), "nao-existe", "FileScan.Worker.dll");
        }));

        AssertVerdict(ScanVerdict.Clean, await Scan(service, "ok.pdf", Samples.CleanPdf()), "InProcess");
        Assert.Null(service.Isolated);
    }

    [Fact]
    public void WorkerOptions_AreValidated()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new FileScanService(new FileScannerOptions { WorkerTimeout = TimeSpan.Zero }));
        Assert.Throws<ArgumentOutOfRangeException>(() => new FileScanService(new FileScannerOptions { WorkerPoolSize = 0 }));
        Assert.Throws<ArgumentOutOfRangeException>(() => new FileScanService(new FileScannerOptions { WorkerRecycleAfterScans = 0 }));
        Assert.Throws<ArgumentOutOfRangeException>(() => new FileScanService(new FileScannerOptions { WorkerMaxMemoryBytes = 1024 }));
        Assert.Throws<ArgumentOutOfRangeException>(() => new FileScanService(new FileScannerOptions { Isolation = (IsolationMode)99 }));
    }

    // ------------------------------------------------------------------ antivírus continua no hospedeiro

    [Fact]
    public async Task Antivirus_StillRunsInTheHost_AndPrevailsOverAnIsolationFailure()
    {
        var malicious = new StubVirusScanner(ScanVerdict.Malicious, "EICAR");
        var failing = new FileScanService(Options(fakeWorker: true), virusScanner: malicious);
        var response = await Scan(failing, "die-x.pdf", Samples.CleanPdf());
        AssertVerdict(ScanVerdict.Malicious, response, "AV malicioso prevalece sobre NotInspected");
        Assert.Equal(1, malicious.Calls);

        var clean = new StubVirusScanner(ScanVerdict.Clean, null);
        var ok = new FileScanService(Options(fakeWorker: false), virusScanner: clean);
        var okResponse = await Scan(ok, "ok.pdf", Samples.CleanPdf());
        AssertVerdict(ScanVerdict.Clean, okResponse, "AV limpo + inspeção integral");
        Assert.Equal(1, clean.Calls);

        var crashWithCleanAv = new FileScanService(Options(fakeWorker: true), virusScanner: new StubVirusScanner(ScanVerdict.Clean, null));
        AssertVerdict(ScanVerdict.NotInspected, await Scan(crashWithCleanAv, "die-x.pdf", Samples.CleanPdf()),
            "AV limpo NUNCA promove uma falha de isolamento a Clean");
    }

    // ------------------------------------------------------------------ limites do SO e higiene do protocolo

    [Fact]
    public async Task MemoryCap_KillsOrFailsTheWorker_NotInspected()
    {
        var service = new FileScanService(Options(fakeWorker: true, o => o.WorkerMaxMemoryBytes = 256L * 1024 * 1024));
        AssertVerdict(ScanVerdict.Clean, await Scan(service, "antes.pdf", Samples.CleanPdf()), "aquecimento");

        var response = await Scan(service, "alloc-x.pdf", Samples.CleanPdf()); // tenta reter ~4 GiB

        AssertVerdict(ScanVerdict.NotInspected, response, "worker acima do teto de memória");
        AssertVerdict(ScanVerdict.Clean, await Scan(service, "depois.pdf", Samples.CleanPdf()), "scan depois do teto");
    }

    [Fact]
    public async Task OnWindows_TheWorkerRunsInsideAJobObject()
    {
        if (!OperatingSystem.IsWindows()) return; // Job Object é do Windows; no Linux o limite é só o teto do GC (documentado)

        var service = new FileScanService(Options(fakeWorker: false));
        AssertVerdict(ScanVerdict.Clean, await Scan(service, "ok.pdf", Samples.CleanPdf()), "aquecimento");
        int pid = Assert.Single(PoolOf(service).LivePids);

        using var process = Process.GetProcessById(pid);
        Assert.True(IsProcessInJob(process.Handle, 0, out bool inJob) && inJob, "o worker deveria estar em um Job Object");
    }

    [Fact]
    public async Task WorkerStdout_CarriesOnlyTheProtocol()
    {
        var launch = WorkerLocator.Resolve(null, out var error);
        Assert.True(launch is not null, "worker real não localizado: " + error);

        var info = new ProcessStartInfo(launch!.HostPath)
        {
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        info.ArgumentList.Add(launch.WorkerDll);
        using var process = Process.Start(info)!;
        _ = process.StandardError.ReadToEndAsync();
        var stdout = process.StandardOutput.BaseStream;

        var hello = await Bounded(WorkerProtocol.ReadFrameAsync(stdout, WorkerProtocol.MaxHeaderBytes, CancellationToken.None), "handshake");
        Assert.NotNull(hello);

        byte[] content = Samples.CleanPdf();
        var request = new WorkerRequest("ok.pdf", content.LongLength, WorkerContentOptions.From(new FileScannerOptions()));
        await WorkerProtocol.WriteFrameAsync(process.StandardInput.BaseStream, WorkerProtocol.Serialize(request), CancellationToken.None);
        await process.StandardInput.BaseStream.WriteAsync(content);
        await process.StandardInput.BaseStream.FlushAsync();
        var frame = await Bounded(WorkerProtocol.ReadFrameAsync(stdout, WorkerProtocol.MaxResponseBytes, CancellationToken.None), "resposta");
        Assert.NotNull(WorkerProtocol.Deserialize<WorkerResponse>(frame!)?.Outcome);

        process.StandardInput.Close(); // EOF => o worker encerra com 0
        using var drain = new MemoryStream();
        await Bounded(stdout.CopyToAsync(drain).ContinueWith(_ => 0), "dreno do stdout");
        Assert.True(process.WaitForExit(30_000), "o worker deveria sair quando o stdin fecha");
        Assert.Equal(0, process.ExitCode);
        Assert.Equal(0, drain.Length); // nenhum byte além dos quadros do protocolo
    }

    [Theory]
    [InlineData("--host")]            // vigia do PID pai + Job Object (Windows)
    [InlineData("--host-nowatchdog")] // SÓ o Job Object: prova o KILL_ON_JOB_CLOSE (Windows); nos demais SO não há garantia
    public async Task WorkerDoesNotSurviveItsHost(string mode)
    {
        if (mode == "--host-nowatchdog" && !OperatingSystem.IsWindows()) return; // sem Job Object nem vigia: órfão possível (documentado)

        // O hospedeiro descartável inicia um scan que TRAVA no worker; matamos o hospedeiro (sem a árvore) e o
        // worker, que nunca lê o stdin, tem de morrer sozinho.
        var info = new ProcessStartInfo("dotnet")
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
        };
        info.ArgumentList.Add(FakeWorkerPath());
        info.ArgumentList.Add(mode);
        using var host = Process.Start(info)!;
        int workerPid = 0;
        try
        {
            var line = await Bounded(host.StandardOutput.ReadLineAsync(), "PID do worker");
            Assert.True(line is not null && line.StartsWith("PID ", StringComparison.Ordinal), $"saída inesperada do hospedeiro: '{line}'");
            workerPid = int.Parse(line![4..]);
            Assert.True(IsAlive(workerPid));

            host.Kill(entireProcessTree: false);
            host.WaitForExit(10_000);

            Assert.True(await WaitUntil(() => !IsAlive(workerPid), TimeSpan.FromSeconds(30)),
                "o worker sobreviveu órfão à morte do hospedeiro");
        }
        finally
        {
            if (!host.HasExited) host.Kill(entireProcessTree: true);
            if (workerPid != 0 && IsAlive(workerPid))
            {
                using var orphan = Process.GetProcessById(workerPid); // PID criado por este teste
                orphan.Kill(entireProcessTree: true);
            }
        }
    }

    // ------------------------------------------------------------------ auxiliares

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsProcessInJob(nint process, nint job, [MarshalAs(UnmanagedType.Bool)] out bool result);

    private sealed class StubVirusScanner(ScanVerdict verdict, string? reason) : IVirusScanner
    {
        public int Calls;
        public string Name => "stub-av";

        public Task<(ScanVerdict Verdict, string? Reason)> ScanAsync(Stream content, CancellationToken ct)
        {
            Interlocked.Increment(ref Calls);
            return Task.FromResult((verdict, reason));
        }
    }
}
