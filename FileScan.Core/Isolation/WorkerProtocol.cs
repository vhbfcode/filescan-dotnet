using System.Buffers.Binary;
using System.Text.Json;

namespace FileScan.Scanning;

/// <summary>
/// Protocolo pai - worker sobre stdin/stdout. Uma mensagem por scan.
/// Pedido:   [int32 LE tamanho][cabeçalho JSON <see cref="WorkerRequest"/>][ContentLength bytes brutos].
/// Resposta: [int32 LE tamanho][JSON <see cref="WorkerResponse"/>].
/// Na partida o worker emite um quadro <see cref="WorkerHello"/> (mesmo enquadramento de resposta).
/// O stdout do worker carrega SÓ isto: o <c>Console.Out</c> dele é redirecionado para stderr.
/// </summary>
internal static class WorkerProtocol
{
    public const int Version = 1;
    public const int MaxHeaderBytes = 1 << 20;
    public const int MaxResponseBytes = 32 << 20;

    public static readonly JsonSerializerOptions Json = new()
    {
        PropertyNameCaseInsensitive = false,
    };

    public static async Task WriteFrameAsync(Stream stream, byte[] payload, CancellationToken ct)
    {
        var prefix = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(prefix, payload.Length);
        await stream.WriteAsync(prefix, ct);
        await stream.WriteAsync(payload, ct);
    }

    /// <summary>Lê um quadro. <c>null</c> = EOF limpo ANTES do primeiro byte; truncado/gigante = exceção.</summary>
    public static async Task<byte[]?> ReadFrameAsync(Stream stream, int maxBytes, CancellationToken ct)
    {
        var prefix = new byte[4];
        int got = 0;
        while (got < 4)
        {
            int read = await stream.ReadAsync(prefix.AsMemory(got, 4 - got), ct);
            if (read == 0)
            {
                if (got == 0) return null;
                throw new EndOfStreamException("quadro truncado no prefixo de tamanho");
            }
            got += read;
        }

        int length = BinaryPrimitives.ReadInt32LittleEndian(prefix);
        if (length < 0 || length > maxBytes)
            throw new InvalidDataException($"tamanho de quadro inválido ({length})");

        var payload = new byte[length];
        await stream.ReadExactlyAsync(payload, ct); // EndOfStreamException se truncar
        return payload;
    }

    public static byte[] Serialize<T>(T value) => JsonSerializer.SerializeToUtf8Bytes(value, Json);

    public static T? Deserialize<T>(byte[] payload) => JsonSerializer.Deserialize<T>(payload, Json);
}

/// <summary>Subconjunto das opções que o estágio de conteúdo usa (nada de caminhos/callbacks do hospedeiro).</summary>
internal sealed record WorkerContentOptions(
    long MaxFileSizeBytes,
    long MaxDecompressedBytesPerStream,
    long MaxTotalDecompressedBytes,
    int MaxContainerEntries,
    int MaxPdfObjects,
    int MaxEmbeddedFiles,
    int MaxEmbeddedDepth,
    string[] AllowedExtensions,
    ActiveContentAction OnActiveContent)
{
    public static WorkerContentOptions From(FileScannerOptions o) => new(
        o.MaxFileSizeBytes, o.MaxDecompressedBytesPerStream, o.MaxTotalDecompressedBytes, o.MaxContainerEntries,
        o.MaxPdfObjects, o.MaxEmbeddedFiles, o.MaxEmbeddedDepth, [.. o.AllowedExtensions], o.OnActiveContent);

    /// <summary>Sempre <see cref="IsolationMode.InProcess"/>: o worker nunca cria outro worker.</summary>
    public FileScannerOptions ToOptions() => new()
    {
        MaxFileSizeBytes = MaxFileSizeBytes,
        MaxDecompressedBytesPerStream = MaxDecompressedBytesPerStream,
        MaxTotalDecompressedBytes = MaxTotalDecompressedBytes,
        MaxContainerEntries = MaxContainerEntries,
        MaxPdfObjects = MaxPdfObjects,
        MaxEmbeddedFiles = MaxEmbeddedFiles,
        MaxEmbeddedDepth = MaxEmbeddedDepth,
        AllowedExtensions = AllowedExtensions,
        OnActiveContent = OnActiveContent,
        Isolation = IsolationMode.InProcess,
    };
}

internal sealed record WorkerRequest(string FileName, long ContentLength, WorkerContentOptions Options);

/// <summary>Ou <see cref="Outcome"/> ou <see cref="Error"/> (exceção inesperada no worker).</summary>
internal sealed record WorkerResponse(ContentOutcome? Outcome, string? Error);

internal sealed record WorkerHello(int Protocol, int Pid);
