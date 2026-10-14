namespace FileScan.Scanning;

/// <summary>
/// Executa o estágio de conteúdo ativo da <see cref="FileScanService"/> (onde o PdfPig abre o PDF) em um
/// processo filho <c>FileScan.Worker</c>, com pool de workers quentes. É o que sustenta
/// <see cref="IsolationMode.Worker"/>: <see cref="FileScanService"/> o usa por dentro; use-o diretamente
/// para um scan isolado sem antivírus.
/// <para>
/// Contrato fail-closed: worker ausente, impossível de iniciar, que morre (estouro de pilha, OOM), que
/// estoura <see cref="FileScannerOptions.WorkerTimeout"/>, que devolve resposta inválida ou fluxo truncado
/// resulta em <see cref="ScanVerdict.NotInspected"/> — nunca <see cref="ScanVerdict.Clean"/> — e o processo
/// hospedeiro segue vivo. O pai mata a árvore de processos do worker, que é reiniciado no scan seguinte.
/// Cancelamento do chamador é propagado como <see cref="OperationCanceledException"/>.
/// </para>
/// </summary>
public sealed class IsolatedFileScanService
{
    private readonly FileScannerOptions _opt;
    private readonly object _gate = new();
    private WorkerLaunch? _launch;
    private FileScanService? _facade;

    /// <summary>Cria o executor com as opções de worker de <paramref name="options"/> (o worker só é iniciado no 1º scan).</summary>
    public IsolatedFileScanService(FileScannerOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        _opt = options.Snapshot();
        _opt.Validate();
    }

    /// <summary>
    /// Scan completo (estrutural + conteúdo ativo, este no worker), sem antivírus, SEMPRE isolado —
    /// ignora <see cref="FileScannerOptions.Isolation"/> = InProcess.
    /// </summary>
    public Task<ScanResponse> ScanAsync(string fileName, byte[] content, CancellationToken ct = default)
    {
        FileScanService facade;
        lock (_gate)
        {
            if (_facade is null)
            {
                var forced = _opt.Snapshot();
                forced.Isolation = IsolationMode.Worker;
                _facade = new FileScanService(forced);
            }

            facade = _facade;
        }

        return facade.ScanAsync(fileName, content, ct);
    }

    internal WorkerPool? Pool { get; private set; }

    internal async Task<ContentOutcome> InspectContentAsync(string fileName, byte[] content, long size, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var launch = ResolveLaunch(out var configurationError);
        if (launch is null)
        {
            Log($"erro de configuração do isolamento: {configurationError}");
            return ContentOutcome.Failed($"erro de configuração do isolamento (FileScan.Worker): {configurationError}", size);
        }

        var pool = Pool = WorkerPool.GetOrCreate(launch, _opt.WorkerPoolSize, _opt.WorkerRecycleAfterScans,
            _opt.WorkerMaxMemoryBytes);
        var request = new WorkerRequest(fileName, content.LongLength, WorkerContentOptions.From(_opt));

        var result = await pool.RunAsync(request, content, _opt.WorkerTimeout, ct);
        if (result.Failure is not null)
        {
            Log($"falha de isolamento ({fileName}): {result.Diagnostic ?? result.Failure}");
            return ContentOutcome.Failed(result.Failure, size);
        }

        var outcome = result.Response!.Outcome;
        var problem = outcome is null ? "resposta do worker sem resultado" : outcome.ValidationProblem(size);
        if (problem is not null)
        {
            Log($"resposta inválida do worker ({fileName}): {problem}");
            return ContentOutcome.Failed(problem, size);
        }

        return outcome!;
    }

    private WorkerLaunch? ResolveLaunch(out string? error)
    {
        var cached = Volatile.Read(ref _launch);
        if (cached is not null)
        {
            error = null;
            return cached;
        }

        // Só o sucesso é cacheado: corrigir o empacotamento e tentar de novo funciona sem reiniciar o app.
        var launch = WorkerLocator.Resolve(_opt.WorkerPath, out error);
        if (launch is not null) Volatile.Write(ref _launch, launch);
        return launch;
    }

    private void Log(string message)
    {
        try { _opt.OnIsolationEvent?.Invoke(Sanitize(message)); }
        catch (Exception) { /* log do chamador nunca quebra o scan */ }
    }

    /// <summary>
    /// A mensagem carrega o nome do arquivo e o stderr do worker, ambos derivados de entrada hostil: troca
    /// caracteres de controle (quebras de linha forjariam entradas de log) e limita o tamanho.
    /// </summary>
    internal static string Sanitize(string message)
    {
        const int Max = 2000;
        var builder = new System.Text.StringBuilder(Math.Min(message.Length, Max));
        foreach (char c in message)
        {
            if (builder.Length >= Max) { builder.Append("..."); break; }
            builder.Append(char.IsControl(c) ? ' ' : c);
        }

        return builder.ToString();
    }
}
