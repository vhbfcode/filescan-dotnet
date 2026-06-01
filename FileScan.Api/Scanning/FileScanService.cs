using Microsoft.Extensions.Options;

namespace FileScan.Scanning;

/// <summary>
/// Orquestra a validação: estrutural (barata) primeiro, antivírus depois.
/// </summary>
public sealed class FileScanService(
    StructuralValidator structural,
    ClamAvScanner clamav,
    IOptions<FileScanOptions> options)
{
    private readonly FileScanOptions _opt = options.Value;

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
        var structuralReason = structural.Validate(fileName, bytes);
        if (structuralReason is not null)
            return Build(fileName, size, ScanVerdict.Rejected, structuralReason);

        // 2) Conteúdo ativo (PDF, Office, CSV, imagens) — heurística multi-formato.
        IReadOnlyList<string>? warnings = null;
        if (_opt.ActiveContent.OnDetected != ActiveContentAction.Ignore)
        {
            var findings = new List<string>(ActiveContentInspector.Inspect(fileName, bytes));

            // 2b) PDF: inspeciona recursivamente os arquivos embutidos (anexos). Anexo benigno (XML/dados)
            //     passa; anexo perigoso (exe/script/macro/PDF com JS) é pego, com motivo preciso.
            if (ActiveContentInspector.Detect(fileName, bytes) == FileKind.Pdf)
            {
                foreach (var embedded in PdfEmbeddedFileExtractor.Extract(bytes))
                {
                    var sub = InspectEmbedded(embedded);
                    if (sub is not null) findings.Add($"arquivo embutido — {sub}");
                }
            }

            if (findings.Count > 0)
            {
                var msg = "Conteúdo ativo detectado: " + string.Join("; ", findings);
                if (_opt.ActiveContent.OnDetected == ActiveContentAction.Reject)
                    return Build(fileName, size, ScanVerdict.Rejected, msg);

                warnings = [msg]; // Flag: segue para o AV, mas avisa o caller.
            }
        }

        // 3) Antivírus — camada OPCIONAL. Desligada = roda só estrutural + conteúdo ativo (sem clamd/container).
        if (!_opt.ClamAv.Enabled)
            return Build(fileName, size, ScanVerdict.Clean, reason: null, warnings);

        using var avStream = new MemoryStream(bytes, writable: false);
        var (verdict, reason) = await clamav.ScanAsync(avStream, ct);
        return Build(fileName, size, verdict, reason, warnings, engine: "clamav");
    }

    // Inspeção recursiva (1 nível) de um anexo de PDF: tipo perigoso (Mime-Detective) + conteúdo ativo.
    private string? InspectEmbedded(byte[] content)
    {
        var dangerous = structural.DangerousContentType(content);
        if (dangerous is not null)
            return $"tipo perigoso ('{dangerous}')";

        var sub = ActiveContentInspector.Inspect("", content);
        return sub.Count > 0 ? string.Join("; ", sub) : null;
    }

    private static ScanResponse Build(string fileName, long size, ScanVerdict verdict, string? reason,
        IReadOnlyList<string>? warnings = null, string engine = "filescan") =>
        new(fileName, size, verdict, reason, Engine: engine, ScannedAtUtc: DateTime.UtcNow.ToString("O"), Warnings: warnings);
}
