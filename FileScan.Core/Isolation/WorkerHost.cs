using System.Text.Json;

namespace FileScan.Scanning;

/// <summary>
/// Laço do processo worker: lê um pedido, roda a <see cref="FileScanService"/> (estágio de conteúdo,
/// com a guarda pré-Open como primeira camada) e responde. Termina com exit 0 quando o pai fecha o stdin.
/// Um estouro de pilha no <c>PdfDocument.Open</c> mata ESTE processo — é para isso que ele existe.
/// </summary>
internal static class WorkerHost
{
    /// <param name="input">stdin bruto.</param>
    /// <param name="output">stdout bruto — só o protocolo pode ser escrito aqui.</param>
    /// <param name="beforeRequest">Gancho de teste (worker falso); o executável de produção passa <c>null</c>.</param>
    public static async Task<int> RunAsync(Stream input, Stream output,
        Func<WorkerRequest, Task>? beforeRequest = null)
    {
        await WorkerProtocol.WriteFrameAsync(output,
            WorkerProtocol.Serialize(new WorkerHello(WorkerProtocol.Version, Environment.ProcessId)),
            CancellationToken.None);
        await output.FlushAsync();

        StartParentWatchdog();

        var services = new Dictionary<string, FileScanService>(StringComparer.Ordinal);
        while (true)
        {
            var headerBytes = await WorkerProtocol.ReadFrameAsync(input, WorkerProtocol.MaxHeaderBytes, CancellationToken.None);
            if (headerBytes is null) return 0; // o pai fechou o stdin (ou morreu): encerra.

            var request = WorkerProtocol.Deserialize<WorkerRequest>(headerBytes)
                ?? throw new InvalidDataException("cabeçalho de pedido vazio");
            if (request.ContentLength < 0 || request.ContentLength > Array.MaxLength)
                throw new InvalidDataException($"ContentLength inválido ({request.ContentLength})");

            var content = new byte[request.ContentLength];
            await input.ReadExactlyAsync(content);

            WorkerResponse response;
            try
            {
                if (beforeRequest is not null) await beforeRequest(request);
                var key = JsonSerializer.Serialize(request.Options, WorkerProtocol.Json);
                if (!services.TryGetValue(key, out var service))
                {
                    if (services.Count >= 8) services.Clear();
                    service = new FileScanService(request.Options.ToOptions());
                    services[key] = service;
                }

                var outcome = service.InspectContentInProcess(request.FileName, content, content.LongLength, CancellationToken.None);
                response = new WorkerResponse(outcome, null);
            }
            catch (Exception ex)
            {
                // O pai trata erro como falha de isolamento (NotInspected) e recicla este worker.
                response = new WorkerResponse(null, $"{ex.GetType().Name}: {ex.Message}");
            }

            await WorkerProtocol.WriteFrameAsync(output, WorkerProtocol.Serialize(response), CancellationToken.None);
            await output.FlushAsync();
        }
    }

    /// <summary>Variável de ambiente com o PID do processo pai, definida pelo hospedeiro ao iniciar o worker.</summary>
    internal const string ParentPidVariable = "FILESCAN_PARENT_PID";

    /// <summary>
    /// Se o pai morrer (crash, kill), o worker não pode sobreviver órfão — nem preso em um laço de CPU que nunca
    /// lê o stdin. Em Windows o Job Object (KILL_ON_JOB_CLOSE) já cobre; este vigia cobre também Linux/macOS.
    /// </summary>
    private static void StartParentWatchdog()
    {
        if (!int.TryParse(Environment.GetEnvironmentVariable(ParentPidVariable), out int parentPid)) return;

        var thread = new Thread(() =>
        {
            try
            {
                using var parent = System.Diagnostics.Process.GetProcessById(parentPid);
                parent.WaitForExit();
            }
            catch (ArgumentException)
            {
                // o pai já tinha saído
            }
            catch (InvalidOperationException)
            {
            }

            Environment.Exit(3);
        })
        { IsBackground = true, Name = "filescan-parent-watchdog" };
        thread.Start();
    }
}
