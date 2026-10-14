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

    /// <summary>Default de <see cref="MaxContainerEntries"/>: 1.024 entradas de container (OOXML).</summary>
    public const int DefaultMaxContainerEntries = 1024;

    /// <summary>Default de <see cref="MaxPdfObjects"/>: 50.000 objetos PDF por scan.</summary>
    public const int DefaultMaxPdfObjects = 50_000;

    /// <summary>Default de <see cref="MaxEmbeddedFiles"/>: 50 anexos por scan.</summary>
    public const int DefaultMaxEmbeddedFiles = 50;

    /// <summary>Default de <see cref="MaxEmbeddedDepth"/>: três níveis de PDF embutido.</summary>
    public const int DefaultMaxEmbeddedDepth = 3;

    /// <summary>Default de <see cref="WorkerTimeout"/>: 20 segundos por scan.</summary>
    public static readonly TimeSpan DefaultWorkerTimeout = TimeSpan.FromSeconds(20);

    /// <summary>Default de <see cref="WorkerRecycleAfterScans"/>: o worker é reciclado a cada 100 scans.</summary>
    public const int DefaultWorkerRecycleAfterScans = 100;

    /// <summary>Default de <see cref="WorkerMaxMemoryBytes"/>: 2 GiB por worker.</summary>
    public const long DefaultWorkerMaxMemoryBytes = 2L * 1024 * 1024 * 1024;

    internal const int MaxSupportedWorkerPoolSize = 32;

    internal const long MaxSupportedFileSizeBytes = 2L * 1024 * 1024 * 1024;
    internal const long MaxSupportedDecompressedBytesPerStream = 256L * 1024 * 1024;
    internal const long MaxSupportedTotalDecompressedBytes = 1024L * 1024 * 1024;
    internal const int MaxSupportedContainerEntries = 100_000;
    internal const int MaxSupportedPdfObjects = 1_000_000;
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

    /// <summary>Quantidade agregada máxima de entradas de container (OOXML) por scan. Os objetos de PDF têm limite próprio: <see cref="MaxPdfObjects"/>.</summary>
    public int MaxContainerEntries { get; set; } = DefaultMaxContainerEntries;

    /// <summary>
    /// Quantidade agregada máxima de objetos PDF (inclui os dos PDFs embutidos) por scan. Separada
    /// de <see cref="MaxContainerEntries"/>, que continua valendo para entradas de container (OOXML):
    /// PDFs reais de seguradora/ERP passam de 1.024 objetos com facilidade.
    /// </summary>
    public int MaxPdfObjects { get; set; } = DefaultMaxPdfObjects;

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

    /// <summary>
    /// ONDE o conteúdo é inspecionado. O default é <see cref="IsolationMode.Worker"/>: o
    /// <c>PdfDocument.Open</c> do PdfPig recursa sem limite e um estouro de pilha NÃO é capturável —
    /// derruba o processo hospedeiro; a única defesa robusta é rodá-lo em um processo filho.
    /// <see cref="IsolationMode.InProcess"/> é INSEGURO para PDF hostil e existe só para testes e
    /// ambientes que não podem criar processos filhos e aceitam o risco.
    /// </summary>
    public IsolationMode Isolation { get; set; } = IsolationMode.Worker;

    /// <summary>
    /// Tempo máximo de UM scan no worker (default 20 s). Estourar mata a árvore de processos do worker,
    /// reinicia-o e devolve <see cref="ScanVerdict.NotInspected"/>. Só vale com <see cref="IsolationMode.Worker"/>.
    /// </summary>
    public TimeSpan WorkerTimeout { get; set; } = DefaultWorkerTimeout;

    /// <summary>
    /// Quantidade de workers quentes do pool (scans simultâneos). Default: metade dos núcleos, entre 1 e 4.
    /// O pool é compartilhado por todas as instâncias com a mesma configuração de worker no processo.
    /// </summary>
    public int WorkerPoolSize { get; set; } = Math.Clamp(Environment.ProcessorCount / 2, 1, 4);

    /// <summary>Recicla (encerra e recria) o worker a cada N scans, limitando vazamento/fragmentação. Default 100.</summary>
    public int WorkerRecycleAfterScans { get; set; } = DefaultWorkerRecycleAfterScans;

    /// <summary>
    /// Teto de memória por worker, em bytes (0 = sem teto). Windows: limite do Job Object (memória
    /// comprometida do processo) + teto do heap do GC; outros SO: SOMENTE o teto do heap do GC
    /// (<c>DOTNET_GCHeapHardLimit</c>) — best-effort, não cobre memória nativa. Default 2 GiB.
    /// </summary>
    public long WorkerMaxMemoryBytes { get; set; } = DefaultWorkerMaxMemoryBytes;

    /// <summary>
    /// Caminho explícito do <c>FileScan.Worker.dll</c>. Vazio = <c>filescan-worker/FileScan.Worker.dll</c>
    /// ao lado do <c>FileScan.Core.dll</c> (onde o pacote NuGet o coloca, inclusive após <c>dotnet publish</c>).
    /// </summary>
    public string? WorkerPath { get; set; }

    /// <summary>
    /// Callback opcional para registrar eventos de isolamento (worker ausente/mal configurado, crash,
    /// timeout, resposta inválida). Exceções do callback são engolidas. Use para o seu log.
    /// </summary>
    public Action<string>? OnIsolationEvent { get; set; }

    internal FileScannerOptions Snapshot() => new()
    {
        MaxFileSizeBytes = MaxFileSizeBytes,
        MaxDecompressedBytesPerStream = MaxDecompressedBytesPerStream,
        MaxTotalDecompressedBytes = MaxTotalDecompressedBytes,
        MaxContainerEntries = MaxContainerEntries,
        MaxPdfObjects = MaxPdfObjects,
        MaxEmbeddedFiles = MaxEmbeddedFiles,
        MaxEmbeddedDepth = MaxEmbeddedDepth,
        AllowedExtensions = AllowedExtensions is null ? null! : [.. AllowedExtensions],
        OnActiveContent = OnActiveContent,
        Isolation = Isolation,
        WorkerTimeout = WorkerTimeout,
        WorkerPoolSize = WorkerPoolSize,
        WorkerRecycleAfterScans = WorkerRecycleAfterScans,
        WorkerMaxMemoryBytes = WorkerMaxMemoryBytes,
        WorkerPath = WorkerPath,
        OnIsolationEvent = OnIsolationEvent,
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

        if (MaxPdfObjects is <= 0 or > MaxSupportedPdfObjects)
            throw new ArgumentOutOfRangeException(nameof(MaxPdfObjects),
                $"deve estar entre 1 e {MaxSupportedPdfObjects}");

        if (MaxEmbeddedFiles is <= 0 or > MaxSupportedEmbeddedFiles)
            throw new ArgumentOutOfRangeException(nameof(MaxEmbeddedFiles),
                $"deve estar entre 1 e {MaxSupportedEmbeddedFiles}");

        if (MaxEmbeddedDepth is < 0 or > MaxSupportedEmbeddedDepth)
            throw new ArgumentOutOfRangeException(nameof(MaxEmbeddedDepth),
                $"deve estar entre 0 e {MaxSupportedEmbeddedDepth}");

        if (!Enum.IsDefined(OnActiveContent))
            throw new ArgumentOutOfRangeException(nameof(OnActiveContent));

        if (!Enum.IsDefined(Isolation))
            throw new ArgumentOutOfRangeException(nameof(Isolation));

        if (WorkerTimeout <= TimeSpan.Zero || WorkerTimeout > TimeSpan.FromMinutes(30))
            throw new ArgumentOutOfRangeException(nameof(WorkerTimeout), "deve estar entre 1 ms e 30 minutos");

        if (WorkerPoolSize is < 1 or > MaxSupportedWorkerPoolSize)
            throw new ArgumentOutOfRangeException(nameof(WorkerPoolSize),
                $"deve estar entre 1 e {MaxSupportedWorkerPoolSize}");

        if (WorkerRecycleAfterScans < 1)
            throw new ArgumentOutOfRangeException(nameof(WorkerRecycleAfterScans), "deve ser >= 1");

        if (WorkerMaxMemoryBytes != 0 && WorkerMaxMemoryBytes < 64L * 1024 * 1024)
            throw new ArgumentOutOfRangeException(nameof(WorkerMaxMemoryBytes), "deve ser 0 (sem teto) ou >= 64 MiB");

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

/// <summary>Onde a inspeção de conteúdo (e o <c>PdfDocument.Open</c>) é executada.</summary>
public enum IsolationMode
{
    /// <summary>
    /// No processo hospedeiro. ⚠️ INSEGURO para PDF hostil: o PdfPig 0.1.16 pode estourar a pilha de
    /// forma não capturável e derrubar o hospedeiro. A guarda pré-Open reduz, mas é melhor esforço.
    /// </summary>
    InProcess,

    /// <summary>
    /// Em processo filho (<c>FileScan.Worker</c>), com timeout, reciclagem e limites do SO.
    /// Falha do worker ⇒ <see cref="ScanVerdict.NotInspected"/>, jamais <see cref="ScanVerdict.Clean"/>.
    /// Default.
    /// </summary>
    Worker
}
