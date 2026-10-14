using System.Buffers.Binary;
using FileScan.Scanning;

// Dois modos:
//  1) <pasta>      ->  "<arquivo>\t<veredito>" por PDF, em ordem, com flush a cada linha (teste diferencial da guarda).
//  2) (sem args)   ->  WORKER FALSO do protocolo de isolamento: roda o WorkerHost de verdade e, por pedido,
//                      sabota o comportamento conforme o PREFIXO do nome do arquivo (ver FakeBehavior).
//                      Os testes apontam FileScannerOptions.WorkerPath para este assembly.
if (args.Length == 1 && args[0] == "--host")
    return await HostMode.RunAsync();
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
            if (name.StartsWith("wrongsize-", StringComparison.Ordinal))
            {
                var lie = new ContentOutcome(null, false, null, true, null, request.ContentLength + 1);
                await Frame(output, WorkerProtocol.Serialize(new WorkerResponse(lie, null)));
                await Task.Delay(Timeout.Infinite);
            }
        });
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
    /// </summary>
    public static async Task<int> RunAsync()
    {
        var service = new FileScanService(new FileScannerOptions
        {
            WorkerPath = typeof(HostMode).Assembly.Location,
            WorkerTimeout = TimeSpan.FromMinutes(10),
            WorkerRecycleAfterScans = 7_777,
        });
        var scan = service.ScanAsync("hang-x.pdf", System.Text.Encoding.ASCII.GetBytes(
            "%PDF-1.4\n1 0 obj\n<</Type/Catalog/Pages 2 0 R>>\nendobj\n2 0 obj\n<</Type/Pages/Kids[]/Count 0>>\nendobj\n" +
            "trailer\n<</Root 1 0 R>>\nstartxref\n0\n%%EOF\n"));
        for (int i = 0; i < 600 && (service.Isolated?.Pool?.LivePids.Length ?? 0) == 0; i++)
            await Task.Delay(50);
        Console.WriteLine("PID " + service.Isolated!.Pool!.LivePids[0]);
        Console.Out.Flush();
        await scan;
        return 0;
    }
}
