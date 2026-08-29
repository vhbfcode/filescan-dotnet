namespace FileScan.Scanning;

/// <summary>
/// Orquestra a validação: estrutural (barata) primeiro, conteúdo ativo depois, antivírus por último.
/// Ponto de entrada da biblioteca: <c>new FileScanService(new FileScannerOptions())</c> — sem DI,
/// sem daemon, sem API. O antivírus é opcional/plugável (<see cref="IVirusScanner"/>); sem ele,
/// rodam só as camadas estrutural + conteúdo ativo.
/// </summary>
public sealed class FileScanService
{
    private readonly FileScannerOptions _opt;
    private readonly StructuralValidator _structural;
    private readonly IVirusScanner? _virus;

    public FileScanService(FileScannerOptions options, StructuralValidator? structural = null, IVirusScanner? virusScanner = null)
    {
        _opt = options;
        _structural = structural ?? new StructuralValidator(options);
        _virus = virusScanner;
    }

    /// <summary>Conveniência para consumo como biblioteca: valida um conteúdo já em memória.</summary>
    public async Task<ScanResponse> ScanAsync(string fileName, byte[] content, CancellationToken ct = default)
    {
        using var ms = new MemoryStream(content, writable: false);
        return await ScanAsync(fileName, ms, content.LongLength, ct);
    }

    public async Task<ScanResponse> ScanAsync(string fileName, Stream upload, long declaredSize, CancellationToken ct)
    {
        // Barra cedo pelo tamanho declarado, antes de bufferizar um arquivo gigante.
        if (declaredSize > _opt.MaxFileSizeBytes)
            return Build(fileName, declaredSize, ScanVerdict.Rejected,
                $"tamanho {declaredSize} excede o máximo de {_opt.MaxFileSizeBytes} bytes");

        // Bufferiza em memória (limitado pelo tamanho máximo) para inspecionar e escanear
        // exatamente o mesmo conteúdo.
        using var ms = new MemoryStream();
        await upload.CopyToAsync(ms, ct);
        var bytes = ms.ToArray();
        long size = bytes.LongLength;

        // 1) Validação estrutural: tamanho, extensão e tipo real do conteúdo (Mime-Detective).
        var structuralReason = _structural.Validate(fileName, bytes);
        if (structuralReason is not null)
            return Build(fileName, size, ScanVerdict.Rejected, structuralReason);

        // 2) Conteúdo ativo (PDF, Office, CSV, imagens) — heurística multi-formato.
        IReadOnlyList<string>? warnings = null;
        if (_opt.OnActiveContent != ActiveContentAction.Ignore)
        {
            long cap = _opt.MaxDecompressedBytesPerStream;
            var findings = new List<string>(ActiveContentInspector.Inspect(fileName, bytes, cap));

            // 2b) PDF: inspeciona recursivamente os arquivos embutidos (anexos). Anexo benigno (XML/dados)
            //     passa; anexo perigoso (exe/script/macro/PDF com JS) é pego, com motivo preciso.
            if (ActiveContentInspector.Detect(fileName, bytes) == FileKind.Pdf)
            {
                foreach (var embedded in PdfEmbeddedFileExtractor.Extract(bytes, cap))
                {
                    var sub = InspectEmbedded(embedded, cap);
                    if (sub is not null) findings.Add($"arquivo embutido — {sub}");
                }
            }

            if (findings.Count > 0)
            {
                var msg = "Conteúdo ativo detectado: " + string.Join("; ", findings);
                if (_opt.OnActiveContent == ActiveContentAction.Reject)
                    return Build(fileName, size, ScanVerdict.Rejected, msg);

                warnings = [msg]; // Flag: segue para o AV, mas avisa o caller.
            }
        }

        // 3) Antivírus — camada OPCIONAL/plugável. Sem scanner = roda só estrutural + conteúdo ativo.
        if (_virus is null)
            return Build(fileName, size, ScanVerdict.Clean, reason: null, warnings);

        using var avStream = new MemoryStream(bytes, writable: false);
        var (verdict, reason) = await _virus.ScanAsync(avStream, ct);
        return Build(fileName, size, verdict, reason, warnings, engine: _virus.Name);
    }

    // Inspeção recursiva (1 nível) de um anexo de PDF: tipo perigoso (Mime-Detective) + conteúdo ativo.
    private string? InspectEmbedded(byte[] content, long maxDecompressedBytesPerStream)
    {
        var dangerous = _structural.DangerousContentType(content);
        if (dangerous is not null)
            return $"tipo perigoso ('{dangerous}')";

        var sub = ActiveContentInspector.Inspect("", content, maxDecompressedBytesPerStream);
        return sub.Count > 0 ? string.Join("; ", sub) : null;
    }

    private static ScanResponse Build(string fileName, long size, ScanVerdict verdict, string? reason,
        IReadOnlyList<string>? warnings = null, string engine = "filescan") =>
        new(fileName, size, verdict, reason, Engine: engine, ScannedAtUtc: DateTime.UtcNow.ToString("O"), Warnings: warnings);
}
