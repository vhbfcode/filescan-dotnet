namespace FileScan.Scanning;

/// <summary>
/// Orçamento único de trabalho para um scan. A mesma instância atravessa PDF, OOXML e anexos
/// recursivos; criar um orçamento novo por nível quebraria a proteção agregada.
/// </summary>
internal sealed class ScanBudget
{
    private readonly long _maxDecompressedBytesPerStream;
    private readonly long _maxTotalDecompressedBytes;
    private readonly int _maxContainerEntries;
    private readonly int _maxEmbeddedFiles;
    private readonly CancellationToken _cancellationToken;

    public ScanBudget(FileScannerOptions options, CancellationToken cancellationToken = default)
    {
        _maxDecompressedBytesPerStream = options.MaxDecompressedBytesPerStream;
        _maxTotalDecompressedBytes = options.MaxTotalDecompressedBytes;
        _maxContainerEntries = options.MaxContainerEntries;
        _maxEmbeddedFiles = options.MaxEmbeddedFiles;
        _cancellationToken = cancellationToken;
    }

    public long ExpandedBytes { get; private set; }
    public int Entries { get; private set; }
    public int EmbeddedFiles { get; private set; }

    public void ConsumeEntry(string context)
    {
        ThrowIfCancellationRequested();
        Entries++;
        if (Entries > _maxContainerEntries)
            throw new ScanLimitExceededException(
                $"limite agregado de {_maxContainerEntries} entradas/streams excedido ({context})");
    }

    public void ConsumeEmbeddedFile()
    {
        ThrowIfCancellationRequested();
        EmbeddedFiles++;
        if (EmbeddedFiles > _maxEmbeddedFiles)
            throw new ScanLimitExceededException(
                $"limite agregado de {_maxEmbeddedFiles} arquivos embutidos excedido");
    }

    public byte[] ReadExpanded(Stream source, string context)
    {
        ThrowIfCancellationRequested();
        long remainingTotal = _maxTotalDecompressedBytes - ExpandedBytes;
        long allowed = Math.Min(_maxDecompressedBytesPerStream, remainingTotal);
        if (allowed <= 0)
            throw new ScanLimitExceededException(
                $"orçamento agregado de {_maxTotalDecompressedBytes} bytes expandidos esgotado ({context})");

        long sentinelLimit = allowed == long.MaxValue ? long.MaxValue : allowed + 1;
        using var output = new MemoryStream();
        var buffer = new byte[81920];
        long total = 0;

        while (total < sentinelLimit)
        {
            ThrowIfCancellationRequested();
            int toRead = (int)Math.Min(buffer.Length, sentinelLimit - total);
            int read = source.Read(buffer, 0, toRead);
            ThrowIfCancellationRequested();
            if (read == 0) break;
            output.Write(buffer, 0, read);
            total += read;
        }

        // Todo byte efetivamente expandido consome o orçamento, inclusive a sentinela que prova
        // o estouro. Sem essa cobrança, uma sequência de streams grandes poderia falhar
        // individualmente e ainda preservar todo o orçamento agregado para entradas posteriores.
        ExpandedBytes = total > long.MaxValue - ExpandedBytes
            ? long.MaxValue
            : ExpandedBytes + total;

        if (total > _maxDecompressedBytesPerStream)
            throw new ScanLimitExceededException(
                $"limite de {_maxDecompressedBytesPerStream} bytes por stream excedido ({context})");

        if (total > remainingTotal)
            throw new ScanLimitExceededException(
                $"orçamento agregado de {_maxTotalDecompressedBytes} bytes expandidos excedido ({context})");

        ThrowIfCancellationRequested();
        return output.ToArray();
    }

    public byte[] CopyExpanded(ReadOnlyMemory<byte> bytes, string context)
    {
        ThrowIfCancellationRequested();
        using var stream = new MemoryStream(bytes.ToArray(), writable: false);
        return ReadExpanded(stream, context);
    }

    public void ThrowIfCancellationRequested() =>
        _cancellationToken.ThrowIfCancellationRequested();
}

internal sealed class ScanLimitExceededException(string message) : Exception(message);

internal sealed class PdfInspectionException(string message, Exception? innerException = null)
    : Exception(message, innerException);
