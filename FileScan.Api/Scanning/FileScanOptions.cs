using System.ComponentModel.DataAnnotations;

namespace FileScan.Scanning;

/// <summary>
/// Configurações do validador. Bind da seção "FileScan" do appsettings / variáveis de ambiente.
/// </summary>
public sealed class FileScanOptions
{
    public const string SectionName = "FileScan";

    /// <summary>Tamanho máximo aceito, em bytes. Default 25 MB (= StreamMaxLength padrão do ClamAV). Também define o teto do request.</summary>
    [Range(1, 2L * 1024 * 1024 * 1024)]
    public long MaxFileSizeBytes { get; set; } = 25 * 1024 * 1024;

    /// <summary>Máximo de bytes descomprimidos por stream/anexo inspecionado (guarda anti-DoS). Default 16 MB.</summary>
    [Range(64 * 1024, 256L * 1024 * 1024)]
    public long MaxDecompressedBytesPerStream { get; set; } = 16 * 1024 * 1024;

    /// <summary>Orçamento agregado de bytes expandidos em PDF, OOXML e anexos. Default 64 MB.</summary>
    [Range(64 * 1024, 1024L * 1024 * 1024)]
    public long MaxTotalDecompressedBytes { get; set; } = 64 * 1024 * 1024;

    /// <summary>Quantidade agregada máxima de objetos/streams/entradas por scan.</summary>
    [Range(1, 100_000)]
    public int MaxContainerEntries { get; set; } = 1024;

    /// <summary>Quantidade agregada máxima de arquivos embutidos.</summary>
    [Range(1, 10_000)]
    public int MaxEmbeddedFiles { get; set; } = 50;

    /// <summary>Profundidade máxima de PDFs embutidos; a raiz tem profundidade zero.</summary>
    [Range(0, 16)]
    public int MaxEmbeddedDepth { get; set; } = 3;

    /// <summary>
    /// Extensões permitidas (sem ponto, minúsculas). Vazio = não restringe por extensão
    /// (a checagem de assinatura de executável continua valendo de qualquer forma).
    /// </summary>
    public string[] AllowedExtensions { get; set; } = [];

    /// <summary>
    /// Chave exigida no header <c>X-Api-Key</c>. Vazio = autenticação desligada (apenas dev local).
    /// </summary>
    public string ApiKey { get; set; } = string.Empty;

    public ClamAvOptions ClamAv { get; set; } = new();

    public ActiveContentOptions ActiveContent { get; set; } = new();

    public RateLimitOptions RateLimit { get; set; } = new();

    public sealed class ClamAvOptions
    {
        /// <summary>Liga a camada de antivírus. Desligado = só estrutural + conteúdo ativo (sem container/daemon).</summary>
        public bool Enabled { get; set; } = true;

        public string Host { get; set; } = "localhost";
        public int Port { get; set; } = 3310;
    }

    public sealed class ActiveContentOptions
    {
        /// <summary>O que fazer ao detectar conteúdo ativo (JS, macros, DDE, fórmulas, polyglot...).</summary>
        public ActiveContentAction OnDetected { get; set; } = ActiveContentAction.Reject;
    }

    /// <summary>Projeção para as opções da biblioteca (FileScan.Core) — o subconjunto que o scanner usa.</summary>
    public FileScannerOptions ToScannerOptions() => new()
    {
        MaxFileSizeBytes = MaxFileSizeBytes,
        MaxDecompressedBytesPerStream = MaxDecompressedBytesPerStream,
        MaxTotalDecompressedBytes = MaxTotalDecompressedBytes,
        MaxContainerEntries = MaxContainerEntries,
        MaxEmbeddedFiles = MaxEmbeddedFiles,
        MaxEmbeddedDepth = MaxEmbeddedDepth,
        AllowedExtensions = AllowedExtensions,
        OnActiveContent = ActiveContent.OnDetected,
    };

    public sealed class RateLimitOptions
    {
        /// <summary>Liga o rate limiting do endpoint /scan.</summary>
        public bool Enabled { get; set; } = true;

        /// <summary>Máximo de requisições por janela, por cliente (API key, ou IP se não houver chave).</summary>
        [Range(1, 1_000_000)]
        public int PermitLimit { get; set; } = 60;

        /// <summary>Tamanho da janela, em segundos.</summary>
        [Range(1, 86_400)]
        public int WindowSeconds { get; set; } = 60;
    }
}
