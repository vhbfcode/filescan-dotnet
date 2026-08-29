namespace FileScan.Scanning;

/// <summary>
/// Opções do validador (biblioteca). POCO puro, por instância — sem IOptions, sem estado global:
/// dois consumidores no mesmo processo podem usar limites diferentes.
/// </summary>
public sealed class FileScannerOptions
{
    /// <summary>Default de <see cref="MaxFileSizeBytes"/>: 25 MB (= StreamMaxLength padrão do ClamAV).</summary>
    public const long DefaultMaxFileSizeBytes = 25 * 1024 * 1024;

    /// <summary>Default de <see cref="MaxDecompressedBytesPerStream"/>: 16 MB.</summary>
    public const long DefaultMaxDecompressedBytesPerStream = 16 * 1024 * 1024;

    /// <summary>Tamanho máximo aceito, em bytes.</summary>
    public long MaxFileSizeBytes { get; set; } = DefaultMaxFileSizeBytes;

    /// <summary>Máximo de bytes descomprimidos por stream/anexo inspecionado (guarda anti-DoS de "zip bomb").</summary>
    public long MaxDecompressedBytesPerStream { get; set; } = DefaultMaxDecompressedBytesPerStream;

    /// <summary>
    /// Extensões permitidas (sem ponto, minúsculas). Vazio = não restringe por extensão
    /// (a checagem de assinatura de executável continua valendo de qualquer forma).
    /// </summary>
    public string[] AllowedExtensions { get; set; } = [];

    /// <summary>O que fazer ao detectar conteúdo ativo (JS, macros, DDE, fórmulas, polyglot...).</summary>
    public ActiveContentAction OnActiveContent { get; set; } = ActiveContentAction.Reject;
}

/// <summary>Política para conteúdo ativo detectado nos arquivos.</summary>
public enum ActiveContentAction
{
    /// <summary>Recusa o arquivo (Verdict = Rejected). Mais seguro.</summary>
    Reject,

    /// <summary>Deixa passar para o antivírus, mas adiciona um aviso em <c>Warnings</c>. O caller decide.</summary>
    Flag,

    /// <summary>Não inspeciona conteúdo ativo de PDF.</summary>
    Ignore
}
