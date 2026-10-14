using System.Diagnostics;
using System.Globalization;
using System.Text;

namespace FileScan.Scanning;

/// <summary>Falha do worker (crash, resposta inválida, fluxo truncado, não iniciou). Nunca vira Clean.</summary>
internal sealed class WorkerFailureException(string message, Exception? inner = null) : Exception(message, inner);

/// <summary>
/// UM processo worker. Só o PID que ESTE objeto criou é morto (<see cref="Kill"/>), junto da sua árvore.
/// Não é thread-safe: o pool entrega o worker a um scan por vez.
/// </summary>
internal sealed class WorkerProcess : IDisposable
{
    private const int StderrTailBytes = 4096;

    private readonly Process _process;
    private readonly IDisposable? _job;
    private readonly Stream _stdin;
    private readonly Stream _stdout;
    private readonly StringBuilder _stderrTail = new();
    private int _killed;

    public int Pid { get; }
    public int ScansCompleted { get; private set; }
    public bool HasExited
    {
        get
        {
            try { return _process.HasExited; }
            catch (InvalidOperationException) { return true; }
        }
    }

    /// <summary>Últimas linhas do stderr do worker (diagnóstico para o log; nunca vai no ScanResponse).</summary>
    public string StderrTail
    {
        get { lock (_stderrTail) return _stderrTail.ToString(); }
    }

    private WorkerProcess(Process process, IDisposable? job)
    {
        _process = process;
        _job = job;
        _stdin = process.StandardInput.BaseStream;
        _stdout = process.StandardOutput.BaseStream;
        Pid = process.Id;
    }

    /// <summary>Inicia o worker, aplica os limites do SO e espera o handshake. Lança <see cref="WorkerFailureException"/>.</summary>
    public static async Task<WorkerProcess> StartAsync(WorkerLaunch launch, long maxMemoryBytes,
        TimeSpan startTimeout, CancellationToken ct)
    {
        var info = new ProcessStartInfo(launch.HostPath)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        info.ArgumentList.Add(launch.WorkerDll);
        info.Environment["DOTNET_gcServer"] = "0";
        info.Environment["DOTNET_gcConcurrent"] = "0";
        info.Environment["DOTNET_TieredPGO"] = "0";
        info.Environment["DOTNET_CLI_TELEMETRY_OPTOUT"] = "1";
        info.Environment[WorkerHost.ParentPidVariable] = Environment.ProcessId.ToString(CultureInfo.InvariantCulture);
        if (maxMemoryBytes > 0)
        {
            // Teto do heap do GC: vale em QUALQUER SO (o único limite de memória do Linux sem privilégio).
            info.Environment["DOTNET_GCHeapHardLimit"] = maxMemoryBytes.ToString("x", CultureInfo.InvariantCulture);
        }

        Process process;
        try
        {
            process = Process.Start(info) ?? throw new WorkerFailureException("Process.Start devolveu null");
        }
        catch (Exception ex) when (ex is not WorkerFailureException)
        {
            throw new WorkerFailureException($"não foi possível iniciar o worker ('{launch.HostPath}'): {ex.Message}", ex);
        }

        IDisposable? job = null;
        WorkerProcess? worker = null;
        try
        {
            // Teto de memória comprometida do processo = limite do heap + folga para o runtime/JIT/pilhas.
            long processLimit = maxMemoryBytes > 0 ? maxMemoryBytes + 128L * 1024 * 1024 : 0;
            try
            {
                if (launch.LimitApplier is { } applier) job = applier(process, processLimit);
                else if (WindowsJobObject.IsSupported) job = WindowsJobObject.Create(process, processLimit);
            }
            catch (Exception ex)
            {
                // Limite do SO que não pôde ser aplicado NUNCA é ignorado em silêncio: o worker não roda sem ele.
                throw new WorkerFailureException($"não foi possível aplicar os limites do SO ao worker: {ex.Message}", ex);
            }

            worker = new WorkerProcess(process, job);
            process.ErrorDataReceived += (_, e) => worker.AppendStderr(e.Data);
            process.BeginErrorReadLine();

            using var timeout = new CancellationTokenSource(startTimeout);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, timeout.Token);
            using var registration = linked.Token.Register(worker.Kill);
            try
            {
                var frame = await WorkerProtocol.ReadFrameAsync(worker._stdout, WorkerProtocol.MaxHeaderBytes, linked.Token)
                    ?? throw new WorkerFailureException("o worker encerrou antes do handshake" + worker.ExitSuffix());
                var hello = WorkerProtocol.Deserialize<WorkerHello>(frame);
                if (hello is null || hello.Protocol != WorkerProtocol.Version || hello.Pid != process.Id)
                    throw new WorkerFailureException(
                        $"handshake inválido do worker (protocolo {hello?.Protocol.ToString() ?? "?"}, esperado {WorkerProtocol.Version})");
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                throw new WorkerFailureException($"o worker não respondeu ao handshake em {startTimeout.TotalSeconds:0.#}s");
            }
            catch (Exception ex) when (ex is IOException or InvalidDataException or System.Text.Json.JsonException
                                           or ObjectDisposedException or InvalidOperationException)
            {
                throw new WorkerFailureException("falha no handshake com o worker: " + ex.Message + worker.ExitSuffix(), ex);
            }

            return worker;
        }
        catch
        {
            if (worker is not null) worker.Dispose();
            else
            {
                TryKill(process);
                job?.Dispose();
                process.Dispose();
            }
            throw;
        }
    }

    /// <summary>
    /// Uma troca pedido/resposta. O chamador cancela <paramref name="ct"/> para o timeout/cancelamento; isso mata o
    /// worker (a E/S em pipe anônimo não é cancelável de outro jeito). Lança <see cref="WorkerFailureException"/>
    /// para qualquer falha do worker e <see cref="OperationCanceledException"/> quando o token cancelou.
    /// </summary>
    public async Task<WorkerResponse> ExchangeAsync(WorkerRequest request, byte[] content, CancellationToken ct)
    {
        using var registration = ct.Register(Kill);
        try
        {
            await WorkerProtocol.WriteFrameAsync(_stdin, WorkerProtocol.Serialize(request), ct);
            await _stdin.WriteAsync(content, ct);
            await _stdin.FlushAsync(ct);

            var frame = await WorkerProtocol.ReadFrameAsync(_stdout, WorkerProtocol.MaxResponseBytes, ct)
                ?? throw new WorkerFailureException("o worker encerrou sem responder" + ExitSuffix());
            var response = WorkerProtocol.Deserialize<WorkerResponse>(frame)
                ?? throw new WorkerFailureException("resposta vazia do worker");
            ScansCompleted++;
            return response;
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception) when (ct.IsCancellationRequested)
        {
            // Timeout/cancelamento mataram o worker (Kill fecha os pipes): QUALQUER falha de E/S a partir daqui
            // é consequência disso (EOF, IOException, objeto descartado), não um defeito do worker.
            throw new OperationCanceledException(ct);
        }
        catch (Exception ex) when (ex is IOException or EndOfStreamException or InvalidDataException
                                       or System.Text.Json.JsonException or ObjectDisposedException
                                       or InvalidOperationException)
        {
            throw new WorkerFailureException(
                $"o worker falhou ou devolveu resposta inválida ({ex.GetType().Name}){ExitSuffix()}", ex);
        }
    }

    /// <summary>Encerramento cooperativo (fecha o stdin: o worker sai com 0); mata se não sair no prazo.</summary>
    public async Task RetireAsync(TimeSpan grace)
    {
        try
        {
            _stdin.Close();
            using var cts = new CancellationTokenSource(grace);
            await _process.WaitForExitAsync(cts.Token);
        }
        catch (Exception ex) when (ex is OperationCanceledException or IOException or InvalidOperationException
                                       or ObjectDisposedException)
        {
            // cai no Kill
        }
        finally { Dispose(); }
    }

    /// <summary>Mata a árvore de processos DESTE worker (idempotente). Só o PID criado por nós.</summary>
    public void Kill()
    {
        if (Interlocked.Exchange(ref _killed, 1) != 0) return;
        TryKill(_process);
        _job?.Dispose(); // KILL_ON_JOB_CLOSE: cinto e suspensório no Windows.
    }

    public void Dispose()
    {
        Kill();
        try { _process.WaitForExit(3000); } catch (InvalidOperationException) { }
        try { _stdin.Dispose(); } catch (Exception ex) when (ex is IOException or ObjectDisposedException) { }
        _process.Dispose();
    }

    private string ExitSuffix()
    {
        try
        {
            if (_process.WaitForExit(2000))
                return $" (exit code {_process.ExitCode})";
        }
        catch (InvalidOperationException) { }
        return string.Empty;
    }

    private void AppendStderr(string? line)
    {
        if (line is null) return;
        lock (_stderrTail)
        {
            _stderrTail.AppendLine(line);
            if (_stderrTail.Length > StderrTailBytes)
                _stderrTail.Remove(0, _stderrTail.Length - StderrTailBytes);
        }
    }

    private static void TryKill(Process process)
    {
        try { process.Kill(entireProcessTree: true); }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception
                                       or NotSupportedException)
        {
            // já saiu
        }
    }
}
