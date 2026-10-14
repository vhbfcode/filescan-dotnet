using System.Collections.Concurrent;

namespace FileScan.Scanning;

/// <summary>Resultado de um scan no pool: ou a resposta do worker ou o motivo da falha de isolamento.</summary>
internal sealed record PoolResult(WorkerResponse? Response, string? Failure, string? Diagnostic);

/// <summary>
/// Pool de workers QUENTES. Um scan pega um worker livre (ou inicia um, até <c>size</c> simultâneos); worker que
/// morre, estoura o timeout, responde lixo ou lança é MORTO (árvore de processos) e descartado — o próximo scan
/// inicia um novo (reinício). Reciclagem preventiva a cada N scans. Compartilhado entre instâncias do serviço
/// com a mesma configuração de worker, para que milhares de <c>FileScanService</c> não virem milhares de processos.
/// </summary>
internal sealed class WorkerPool
{
    private static readonly ConcurrentDictionary<string, WorkerPool> Pools = new(StringComparer.Ordinal);
    private static readonly TimeSpan StartTimeout = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan RetireGrace = TimeSpan.FromSeconds(2);

    static WorkerPool()
    {
        AppDomain.CurrentDomain.ProcessExit += (_, _) => ShutdownAll();
    }

    private readonly WorkerLaunch _launch;
    private readonly int _recycleAfter;
    private readonly long _maxMemoryBytes;
    private readonly SemaphoreSlim _slots;
    private readonly ConcurrentStack<WorkerProcess> _idle = new();
    private readonly ConcurrentDictionary<int, WorkerProcess> _live = new();
    private int _started;
    private int _killed;
    private int _retired;

    private WorkerPool(WorkerLaunch launch, int size, int recycleAfter, long maxMemoryBytes)
    {
        _launch = launch;
        _recycleAfter = recycleAfter;
        _maxMemoryBytes = maxMemoryBytes;
        _slots = new SemaphoreSlim(size, size);
    }

    public static WorkerPool GetOrCreate(WorkerLaunch launch, int size, int recycleAfter, long maxMemoryBytes) =>
        Pools.GetOrAdd($"{launch.Key}|{size}|{recycleAfter}|{maxMemoryBytes}",
            _ => new WorkerPool(launch, size, recycleAfter, maxMemoryBytes));

    /// <summary>Workers iniciados por este pool desde a criação.</summary>
    public int StartedCount => Volatile.Read(ref _started);

    /// <summary>Workers mortos por falha/timeout/cancelamento.</summary>
    public int KilledCount => Volatile.Read(ref _killed);

    /// <summary>Workers reciclados preventivamente (limite de scans).</summary>
    public int RetiredCount => Volatile.Read(ref _retired);

    /// <summary>PIDs dos workers ociosos (para diagnóstico/testes).</summary>
    public int[] IdlePids => [.. _idle.Select(worker => worker.Pid)];

    /// <summary>PIDs de todos os workers vivos do pool (ociosos ou em scan).</summary>
    public int[] LivePids => [.. _live.Keys];

    /// <exception cref="OperationCanceledException">O <paramref name="ct"/> do chamador cancelou.</exception>
    public async Task<PoolResult> RunAsync(WorkerRequest request, byte[] content, TimeSpan timeout, CancellationToken ct)
    {
        await _slots.WaitAsync(ct);
        WorkerProcess? worker = null;
        bool keep = false;
        bool retire = false;
        try
        {
            worker = TakeIdleLive();
            if (worker is null)
            {
                try
                {
                    worker = await WorkerProcess.StartAsync(_launch, _maxMemoryBytes, StartTimeout, ct);
                    Interlocked.Increment(ref _started);
                    _live[worker.Pid] = worker;
                }
                catch (WorkerFailureException ex)
                {
                    return new PoolResult(null, $"o worker não pôde ser iniciado: {ex.Message}", ex.ToString());
                }
            }

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(timeout);
            WorkerResponse response;
            try
            {
                response = await worker.ExchangeAsync(request, content, cts.Token);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw; // cancelamento do chamador: o worker é morto no finally (estado desconhecido).
            }
            catch (OperationCanceledException)
            {
                return new PoolResult(null,
                    $"timeout de {timeout.TotalSeconds:0.##}s excedido no worker (worker morto e reiniciado)",
                    $"timeout; stderr: {worker.StderrTail}");
            }
            catch (WorkerFailureException ex)
            {
                return new PoolResult(null, $"{ex.Message} (worker morto e reiniciado)",
                    $"{ex.Message}; stderr: {worker.StderrTail}");
            }

            if (response.Error is not null)
            {
                return new PoolResult(null, "exceção inesperada no worker (worker reiniciado)",
                    $"{response.Error}; stderr: {worker.StderrTail}");
            }

            // Resposta bem formada, mas incoerente/mentirosa: o worker não é confiável => morre (não volta ao pool).
            var problem = response.Outcome is null
                ? "resposta do worker sem resultado"
                : response.Outcome.ValidationProblem(content.LongLength);
            if (problem is not null)
            {
                return new PoolResult(null, $"resposta inválida do worker: {problem} (worker morto e reiniciado)",
                    $"resposta inválida: {problem}; stderr: {worker.StderrTail}");
            }

            if (worker.ScansCompleted >= _recycleAfter) retire = true;
            else keep = true;
            return new PoolResult(response, null, null);
        }
        finally
        {
            if (worker is not null)
            {
                if (keep && !worker.HasExited) _idle.Push(worker);
                else if (retire)
                {
                    Interlocked.Increment(ref _retired);
                    _live.TryRemove(worker.Pid, out _);
                    _ = worker.RetireAsync(RetireGrace);
                }
                else
                {
                    Interlocked.Increment(ref _killed);
                    _live.TryRemove(worker.Pid, out _);
                    worker.Dispose();
                }
            }

            _slots.Release();
        }
    }

    private WorkerProcess? TakeIdleLive()
    {
        while (_idle.TryPop(out var candidate))
        {
            if (!candidate.HasExited) return candidate;
            _live.TryRemove(candidate.Pid, out _);
            candidate.Dispose(); // morreu entre scans: descarta e cai no início de um novo
        }

        return null;
    }

    /// <summary>Mata todos os workers ociosos de todos os pools (fim do processo e testes).</summary>
    public static void ShutdownAll()
    {
        foreach (var pool in Pools.Values)
            while (pool._idle.TryPop(out var worker))
                worker.Dispose();
    }
}
