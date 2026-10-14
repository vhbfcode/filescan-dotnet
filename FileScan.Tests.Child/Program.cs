using System.Buffers.Binary;
using FileScan.Scanning;

// Dois modos:
//  1) <pasta>      ->  "<arquivo>\t<veredito>" por PDF, em ordem, com flush a cada linha (teste diferencial da guarda).
//  2) (sem args)   ->  WORKER FALSO do protocolo de isolamento: roda o WorkerHost de verdade e, por pedido,
//                      sabota o comportamento conforme o PREFIXO do nome do arquivo (ver FakeBehavior).
//                      Os testes apontam FileScannerOptions.WorkerPath para este assembly.
if (args.Length == 1 && args[0] is "--host" or "--host-nowatchdog")
    return await HostMode.RunAsync(watchdog: args[0] == "--host");
if (args.Length == 0)
    return await FakeWorker.RunAsync();

var directory = args[0];
var service = new FileScanService(new FileScannerOptions
{
    AllowedExtensions = ["pdf"],
    Isolation = IsolationMode.InProcess, // este filho É o processo descartável do teste diferencial
});
foreach (var file in Directory.GetFiles(directory, "*.pdf").OrderBy(name => name, StringComparer.Ordinal))
{
    var response = await service.ScanAsync("x.pdf", File.ReadAllBytes(file));
    Console.WriteLine($"{Path.GetFileName(file)}\t{response.Verdict}");
    Console.Out.Flush();
}
return 0;

static class FakeWorker
{
    public static async Task<int> RunAsync()
    {
        var output = Console.OpenStandardOutput();
        var input = Console.OpenStandardInput();
        Console.SetOut(Console.Error);

        return await WorkerHost.RunAsync(input, output, async request =>
        {
            string name = request.FileName;

            // "noguard-" desliga a guarda pré-Open SÓ neste pedido: o ataque que ela não pega chega ao PdfDocument.Open.
            PdfStructuralInspector.PreOpenGuardEnabled = !name.StartsWith("noguard-", StringComparison.Ordinal);

            if (name.StartsWith("hang-", StringComparison.Ordinal))
                await Task.Delay(Timeout.Infinite);
            if (name.StartsWith("slow-", StringComparison.Ordinal))
                await Task.Delay(int.Parse(name.Split('-')[1]));
            if (name.StartsWith("die-", StringComparison.Ordinal))
                Environment.Exit(7);
            if (name.StartsWith("alloc-", StringComparison.Ordinal))
            {
                // estoura o teto de memória do worker (DOTNET_GCHeapHardLimit / Job Object)
                var hog = new List<byte[]>();
                for (int i = 0; i < 64; i++) { var chunk = new byte[64 * 1024 * 1024]; Array.Fill(chunk, (byte)1); hog.Add(chunk); }
                GC.KeepAlive(hog);
            }
            if (name.StartsWith("throw-", StringComparison.Ordinal))
                throw new InvalidOperationException("falha simulada no worker");
            if (name.StartsWith("garbage-", StringComparison.Ordinal))
            {
                await Raw(output, "isto nao e um quadro do protocolo"u8.ToArray());
                await Task.Delay(Timeout.Infinite);
            }
            if (name.StartsWith("badjson-", StringComparison.Ordinal))
            {
                await Frame(output, "{\"Outcome\": [oops"u8.ToArray());
                await Task.Delay(Timeout.Infinite);
            }
            if (name.StartsWith("truncated-", StringComparison.Ordinal))
            {
                var prefix = new byte[4];
                BinaryPrimitives.WriteInt32LittleEndian(prefix, 5000);
                await Raw(output, [.. prefix, .. new byte[10]]);
                Environment.Exit(0);
            }
            if (name.StartsWith("liar-", StringComparison.Ordinal))
            {
                // Resposta bem formada, mas MENTINDO: veredito terminal Clean. O pai não pode aceitar.
                var lie = new ContentOutcome(
                    FileScanService.Build(name, request.ContentLength, ScanVerdict.Clean, null),
                    false, null, true, null, request.ContentLength);
                await Frame(output, WorkerProtocol.Serialize(new WorkerResponse(lie, null)));
                await Task.Delay(Timeout.Infinite);
            }
            // Respostas bem formadas que MENTEM contra as invariantes do ContentOutcome (uma regra por prefixo).
            if (name.StartsWith("badincomplete-", StringComparison.Ordinal)) // integral x motivo de incompletude
                await Lie(output, new ContentOutcome(null, false, null, true, "motivo apesar de integral", request.ContentLength));
            if (name.StartsWith("badwarnings-", StringComparison.Ordinal)) // conteúdo ativo x warnings
                await Lie(output, new ContentOutcome(null, true, null, false, "inspeção não concluída: x", request.ContentLength));
            if (name.StartsWith("noreason-", StringComparison.Ordinal)) // terminal Rejected sem motivo
                await Lie(output, ContentOutcome.Finished(FileScanService.Build(name, request.ContentLength, ScanVerdict.Rejected, null)));
            if (name.StartsWith("ignorefull-", StringComparison.Ordinal)) // coerente, mas integral sob Ignore
                await Lie(output, new ContentOutcome(null, false, null, true, null, request.ContentLength));
            if (name.StartsWith("rejectactive-", StringComparison.Ordinal)) // coerente, mas "ativo detectado" sob Reject
                await Lie(output, new ContentOutcome(null, true, ["x"], false, "inspeção não concluída: x", request.ContentLength));
            if (name.StartsWith("flagterminal-", StringComparison.Ordinal)) // terminal Rejected sob Flag
                await Lie(output, ContentOutcome.Finished(FileScanService.Build(name, request.ContentLength, ScanVerdict.Rejected, "motivo")));
            if (name.StartsWith("wrongsize-", StringComparison.Ordinal))
            {
                var lie = new ContentOutcome(null, false, null, true, null, request.ContentLength + 1);
                await Frame(output, WorkerProtocol.Serialize(new WorkerResponse(lie, null)));
                await Task.Delay(Timeout.Infinite);
            }
        });
    }

    private static async Task Lie(Stream output, ContentOutcome outcome)
    {
        await Frame(output, WorkerProtocol.Serialize(new WorkerResponse(outcome, null)));
        await Task.Delay(Timeout.Infinite);
    }

    private static async Task Raw(Stream output, byte[] bytes)
    {
        await output.WriteAsync(bytes);
        await output.FlushAsync();
    }

    private static async Task Frame(Stream output, byte[] payload)
    {
        await WorkerProtocol.WriteFrameAsync(output, payload, CancellationToken.None);
        await output.FlushAsync();
    }
}

static class HostMode
{
    /// <summary>
    /// Hospedeiro descartável: inicia um scan num worker que TRAVA (hang-), imprime o PID do worker e espera.
    /// O teste mata ESTE processo (sem a árvore) e confere que o worker não sobrevive órfão.
    /// Com <c>watchdog: false</c> o vigia do PID pai do worker fica desligado: só o Job Object (Windows) o mata.
    /// </summary>
    public static async Task<int> RunAsync(bool watchdog)
    {
        var launch = WorkerLocator.Resolve(typeof(HostMode).Assembly.Location, out var error)
            ?? throw new InvalidOperationException(error);
        launch = launch with { DisableParentWatchdog = !watchdog };
        var pool = WorkerPool.GetOrCreate(launch, 1, watchdog ? 7_777 : 7_778, FileScannerOptions.DefaultWorkerMaxMemoryBytes);
        var request = new WorkerRequest("hang-x.pdf", 1, WorkerContentOptions.From(new FileScannerOptions()));
        var scan = pool.RunAsync(request, [1], TimeSpan.FromMinutes(10), CancellationToken.None);
        for (int i = 0; i < 600 && pool.LivePids.Length == 0; i++)
            await Task.Delay(50);
        Console.WriteLine("PID " + pool.LivePids[0]);
        Console.Out.Flush();
        await scan;
        return 0;
    }
}
