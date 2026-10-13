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
    private readonly int _maxPdfObjects;
    private readonly CancellationToken _cancellationToken;
    private readonly FileScannerOptions _options;

    public ScanBudget(FileScannerOptions options, CancellationToken cancellationToken = default)
    {
        _maxDecompressedBytesPerStream = options.MaxDecompressedBytesPerStream;
        _maxTotalDecompressedBytes = options.MaxTotalDecompressedBytes;
        _maxContainerEntries = options.MaxContainerEntries;
        _maxEmbeddedFiles = options.MaxEmbeddedFiles;
        _maxPdfObjects = options.MaxPdfObjects;
        _options = options;
        _cancellationToken = cancellationToken;
    }

    /// <summary>
    /// Orçamento novo com os MESMOS limites e o mesmo cancelamento, para a guarda pré-Open: ela
    /// decodifica object streams uma vez e a inspeção real decodifica de novo — somar as duas num
    /// só orçamento cortaria pela metade a capacidade dos PDFs legítimos.
    /// </summary>
    public ScanBudget CreateSibling() => new(_options, _cancellationToken);

    public long ExpandedBytes { get; private set; }
    public int Entries { get; private set; }
    public int EmbeddedFiles { get; private set; }
    public int PdfObjects { get; private set; }

    public void ConsumePdfObject()
    {
        ThrowIfCancellationRequested();
        PdfObjects++;
        if (PdfObjects > _maxPdfObjects)
            throw new ScanLimitExceededException(
                $"limite agregado de {_maxPdfObjects} objetos PDF excedido");
    }

    /// <summary>
    /// Recusa ANTES de decodificar quando o pior caso de saída já não cabe no orçamento (ex.: o
    /// atalho 'z' do ASCII85 expande 1 byte em 4). Não consome orçamento: quem decodifica cobra o
    /// tamanho real depois, com <see cref="CopyExpanded"/>.
    /// </summary>
    public void EnsureCanExpand(long worstCaseBytes, string context)
    {
        ThrowIfCancellationRequested();
        long allowed = Math.Min(_maxDecompressedBytesPerStream, _maxTotalDecompressedBytes - ExpandedBytes);
        if (worstCaseBytes > allowed)
            throw new ScanLimitExceededException(
                $"expansão potencial de {worstCaseBytes} bytes excede o orçamento de {allowed} bytes ({context})");
    }

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
