namespace FileScan.Scanning;

/// <summary>
/// Opções do validador (biblioteca). POCO puro, por instância — sem IOptions, sem estado global.
/// O serviço cria um snapshot validado no construtor; mutações posteriores deste objeto não alteram
/// uma instância de <see cref="FileScanService"/> já construída.
/// </summary>
public sealed class FileScannerOptions
{
    /// <summary>Default de <see cref="MaxFileSizeBytes"/>: 25 MB.</summary>
    public const long DefaultMaxFileSizeBytes = 25 * 1024 * 1024;

    /// <summary>Default de <see cref="MaxDecompressedBytesPerStream"/>: 16 MB.</summary>
    public const long DefaultMaxDecompressedBytesPerStream = 16 * 1024 * 1024;

    /// <summary>Default de <see cref="MaxTotalDecompressedBytes"/>: 64 MB por scan.</summary>
    public const long DefaultMaxTotalDecompressedBytes = 64 * 1024 * 1024;

    /// <summary>Default de <see cref="MaxContainerEntries"/>: 1.024 objetos/entradas/streams.</summary>
    public const int DefaultMaxContainerEntries = 1024;

    /// <summary>Default de <see cref="MaxEmbeddedFiles"/>: 50 anexos por scan.</summary>
    public const int DefaultMaxEmbeddedFiles = 50;

    /// <summary>Default de <see cref="MaxEmbeddedDepth"/>: três níveis de PDF embutido.</summary>
    public const int DefaultMaxEmbeddedDepth = 3;

    internal const long MaxSupportedFileSizeBytes = 2L * 1024 * 1024 * 1024;
    internal const long MaxSupportedDecompressedBytesPerStream = 256L * 1024 * 1024;
    internal const long MaxSupportedTotalDecompressedBytes = 1024L * 1024 * 1024;
    internal const int MaxSupportedContainerEntries = 100_000;
    internal const int MaxSupportedEmbeddedFiles = 10_000;
    internal const int MaxSupportedEmbeddedDepth = 16;

    /// <summary>Tamanho máximo aceito, em bytes.</summary>
    public long MaxFileSizeBytes { get; set; } = DefaultMaxFileSizeBytes;

    /// <summary>Máximo de bytes descomprimidos por stream/anexo inspecionado (guarda anti-DoS de "zip bomb").</summary>
    public long MaxDecompressedBytesPerStream { get; set; } = DefaultMaxDecompressedBytesPerStream;

    /// <summary>
    /// Orçamento agregado de bytes expandidos/copiados de containers por scan. É compartilhado por
    /// PDF, OOXML e todos os anexos recursivos; esgotá-lo produz <see cref="ScanVerdict.NotInspected"/>.
    /// </summary>
    public long MaxTotalDecompressedBytes { get; set; } = DefaultMaxTotalDecompressedBytes;

    /// <summary>Quantidade agregada máxima de objetos, streams e entradas de container por scan.</summary>
    public int MaxContainerEntries { get; set; } = DefaultMaxContainerEntries;

    /// <summary>Quantidade agregada máxima de arquivos embutidos por scan.</summary>
    public int MaxEmbeddedFiles { get; set; } = DefaultMaxEmbeddedFiles;

    /// <summary>Profundidade máxima de PDFs embutidos. A raiz tem profundidade zero.</summary>
    public int MaxEmbeddedDepth { get; set; } = DefaultMaxEmbeddedDepth;

    /// <summary>
    /// Extensões permitidas (sem ponto, minúsculas). Vazio = não restringe por extensão
    /// (a checagem de assinatura de executável continua valendo de qualquer forma).
    /// </summary>
    public string[] AllowedExtensions { get; set; } = [];

    /// <summary>O que fazer ao detectar conteúdo ativo (JS, macros, DDE, fórmulas, polyglot...).</summary>
    public ActiveContentAction OnActiveContent { get; set; } = ActiveContentAction.Reject;

    internal FileScannerOptions Snapshot() => new()
    {
        MaxFileSizeBytes = MaxFileSizeBytes,
        MaxDecompressedBytesPerStream = MaxDecompressedBytesPerStream,
        MaxTotalDecompressedBytes = MaxTotalDecompressedBytes,
        MaxContainerEntries = MaxContainerEntries,
        MaxEmbeddedFiles = MaxEmbeddedFiles,
        MaxEmbeddedDepth = MaxEmbeddedDepth,
        AllowedExtensions = AllowedExtensions is null ? null! : [.. AllowedExtensions],
        OnActiveContent = OnActiveContent,
    };

    internal void Validate()
    {
        if (MaxFileSizeBytes is <= 0 or > MaxSupportedFileSizeBytes)
            throw new ArgumentOutOfRangeException(nameof(MaxFileSizeBytes),
                $"deve estar entre 1 e {MaxSupportedFileSizeBytes}");

        if (MaxDecompressedBytesPerStream is <= 0 or > MaxSupportedDecompressedBytesPerStream)
            throw new ArgumentOutOfRangeException(nameof(MaxDecompressedBytesPerStream),
                $"deve estar entre 1 e {MaxSupportedDecompressedBytesPerStream}");

        if (MaxTotalDecompressedBytes is <= 0 or > MaxSupportedTotalDecompressedBytes)
            throw new ArgumentOutOfRangeException(nameof(MaxTotalDecompressedBytes),
                $"deve estar entre 1 e {MaxSupportedTotalDecompressedBytes}");

        if (MaxDecompressedBytesPerStream > MaxTotalDecompressedBytes)
            throw new ArgumentException(
                $"{nameof(MaxDecompressedBytesPerStream)} não pode exceder {nameof(MaxTotalDecompressedBytes)}");

        if (MaxContainerEntries is <= 0 or > MaxSupportedContainerEntries)
            throw new ArgumentOutOfRangeException(nameof(MaxContainerEntries),
                $"deve estar entre 1 e {MaxSupportedContainerEntries}");

        if (MaxEmbeddedFiles is <= 0 or > MaxSupportedEmbeddedFiles)
            throw new ArgumentOutOfRangeException(nameof(MaxEmbeddedFiles),
                $"deve estar entre 1 e {MaxSupportedEmbeddedFiles}");

        if (MaxEmbeddedDepth is < 0 or > MaxSupportedEmbeddedDepth)
            throw new ArgumentOutOfRangeException(nameof(MaxEmbeddedDepth),
                $"deve estar entre 0 e {MaxSupportedEmbeddedDepth}");

        if (!Enum.IsDefined(OnActiveContent))
            throw new ArgumentOutOfRangeException(nameof(OnActiveContent));

        if (AllowedExtensions is null)
            throw new ArgumentNullException(nameof(AllowedExtensions));
    }
}

/// <summary>Política para conteúdo ativo detectado nos arquivos.</summary>
public enum ActiveContentAction
{
    /// <summary>Recusa o arquivo (Verdict = Rejected). Mais seguro.</summary>
    Reject,

    /// <summary>
    /// Continua até o antivírus, preserva o achado em <c>Warnings</c> e devolve
    /// <see cref="ScanVerdict.ActiveContentDetected"/> se o AV não prevalecer. Nunca devolve Clean.
    /// </summary>
    Flag,

    /// <summary>
    /// Pula a inspeção de conteúdo ativo e, por isso, devolve <see cref="ScanVerdict.NotInspected"/>
    /// se o AV não prevalecer. Nunca devolve Clean.
    /// </summary>
    Ignore
}
