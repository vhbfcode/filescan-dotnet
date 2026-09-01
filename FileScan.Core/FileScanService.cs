namespace FileScan.Scanning;

/// <summary>
/// Orquestra a validação: estrutural (barata) primeiro, conteúdo ativo depois, antivírus por último.
/// Ponto de entrada da biblioteca: <c>new FileScanService(new FileScannerOptions())</c> — sem DI,
/// sem daemon, sem API. O antivírus é opcional/plugável (<see cref="IVirusScanner"/>); sem ele,
/// rodam só as camadas estrutural + conteúdo ativo.
///
/// Contrato de veredito (fail-closed): <see cref="ScanVerdict.Clean"/> SÓ quando a inspeção
/// estrutural/de conteúdo ativo terminou integralmente dentro da política suportada. Trecho que
/// não pôde ser inspecionado (filtro não suportado, criptografia, estrutura inválida, limite
/// interrompido) vira <see cref="ScanVerdict.NotInspected"/> — a ausência de antivírus ou de
/// inspeção nunca vira aceitação. ⚠️ Essa garantia de integralidade cobre <b>PDF e OOXML</b>;
/// para OLE2/imagem/CSV/texto a inspeção é heurística best-effort (ver
/// <see cref="ScanVerdict.Clean"/>).
/// </summary>
public sealed class FileScanService
{
    private readonly FileScannerOptions _opt;
    private readonly StructuralValidator _structural;
    private readonly IVirusScanner? _virus;

    public FileScanService(FileScannerOptions options, StructuralValidator? structural = null, IVirusScanner? virusScanner = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        _opt = options.Snapshot();
        _opt.Validate();
        if (structural is not null && !structural.IsPolicyCompatibleWith(_opt))
            throw new ArgumentException(
                "a política do StructuralValidator injetado diverge de MaxFileSizeBytes ou AllowedExtensions do serviço",
                nameof(structural));

        _structural = structural ?? new StructuralValidator(_opt);
        _virus = virusScanner;
    }

    /// <summary>Conveniência para consumo como biblioteca: valida um conteúdo já em memória.</summary>
    /// <exception cref="OperationCanceledException">O cancelamento foi solicitado antes ou durante a inspeção.</exception>
    public async Task<ScanResponse> ScanAsync(string fileName, byte[] content, CancellationToken ct = default)
    {
        using var ms = new MemoryStream(content, writable: false);
        return await ScanAsync(fileName, ms, content.LongLength, ct);
    }

    /// <summary>
    /// Valida um upload lido de <paramref name="upload"/>.
    /// ⚠️ <paramref name="declaredSize"/> deve ser o tamanho <b>EXATO</b>, em bytes, do conteúdo
    /// que a stream vai entregar (ex.: <c>IFormFile.Length</c>): qualquer divergência entre
    /// declarado e real — nos DOIS sentidos — é tratada como sinal de adulteração e devolve
    /// <see cref="ScanVerdict.Rejected"/>. Quem não tem o tamanho exato (ex.: fonte chunked com
    /// <c>Content-Length</c> aproximado) deve materializar os bytes e usar o overload de
    /// <c>byte[]</c>, que declara o tamanho por construção.
    /// </summary>
    /// <exception cref="OperationCanceledException">O cancelamento foi solicitado durante leitura, parsing, descompressão, recursão ou antivírus.</exception>
    public async Task<ScanResponse> ScanAsync(string fileName, Stream upload, long declaredSize, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        // O tamanho declarado é entrada não confiável: negativo é inválido, e maior que o máximo
        // é barrado cedo — mas nenhum dos dois substitui o limite na LEITURA (abaixo).
        if (declaredSize < 0)
            return Build(fileName, declaredSize, ScanVerdict.Rejected,
                $"tamanho declarado inválido ({declaredSize})");

        if (declaredSize > _opt.MaxFileSizeBytes)
            return Build(fileName, declaredSize, ScanVerdict.Rejected,
                $"tamanho {declaredSize} excede o máximo de {_opt.MaxFileSizeBytes} bytes");

        // Bufferiza em memória com CORTE no máximo+1: a stream nunca é lida além do limite,
        // independentemente do que foi declarado (anti-DoS: declarar pequeno e enviar enorme).
        var (bytes, exceeded) = await ReadBoundedAsync(upload, _opt.MaxFileSizeBytes, ct);
        ct.ThrowIfCancellationRequested();
        long size = bytes.LongLength;

        if (exceeded)
            return Build(fileName, size, ScanVerdict.Rejected,
                $"tamanho real excede o máximo de {_opt.MaxFileSizeBytes} bytes (declarado: {declaredSize})");

        // Divergência declarado × real (nos dois sentidos) é sinal de adulteração — rejeita antes
        // de qualquer inspeção cara.
        if (size != declaredSize)
            return Build(fileName, size, ScanVerdict.Rejected,
                $"tamanho real ({size}) diverge do declarado ({declaredSize})");

        // 1) Validação estrutural: tamanho, extensão e tipo real do conteúdo (Mime-Detective).
        ct.ThrowIfCancellationRequested();
        var structuralReason = _structural.Validate(fileName, bytes);
        ct.ThrowIfCancellationRequested();
        if (structuralReason is not null)
            return Build(fileName, size, ScanVerdict.Rejected, structuralReason);

        // 2) Conteúdo ativo (PDF, Office, CSV, imagens) com um único orçamento agregado.
        IReadOnlyList<string>? warnings = null;
        bool activeContentDetected = false;
        var incomplete = new List<string>();
        var findings = new List<string>();
        var budget = new ScanBudget(_opt, ct);

        if (_opt.OnActiveContent == ActiveContentAction.Ignore)
        {
            incomplete.Add("inspeção de conteúdo ativo pulada pela política Ignore");
        }
        else
        {
            if (ActiveContentInspector.Detect(fileName, bytes) == FileKind.Pdf)
            {
                var pdf = PdfStructuralInspector.Inspect(bytes, budget);
                budget.ThrowIfCancellationRequested();
                findings.AddRange(pdf.Findings);
                incomplete.AddRange(pdf.Incomplete);

                foreach (var embedded in pdf.EmbeddedFiles)
                    InspectEmbedded(embedded, depth: 1, budget, findings, incomplete);
            }
            else
            {
                var inspection = ActiveContentInspector.Inspect(fileName, bytes, budget);
                budget.ThrowIfCancellationRequested();
                findings.AddRange(inspection.Findings);
                incomplete.AddRange(inspection.Incomplete);
            }

            if (findings.Count > 0)
            {
                var msg = "Conteúdo ativo detectado: " + string.Join("; ", findings);
                if (_opt.OnActiveContent == ActiveContentAction.Reject)
                    return Build(fileName, size, ScanVerdict.Rejected, msg);

                activeContentDetected = true;
                warnings = [msg]; // Flag: segue ao AV, mas nunca pode terminar em Clean.
            }
        }

        // Inspeção incompleta NUNCA vira Clean: sem trecho legível não há como afirmar "benigno".
        bool fullyInspected = incomplete.Count == 0;
        string? incompleteReason = fullyInspected
            ? null
            : "inspeção não concluída: " + string.Join("; ", incomplete);

        budget.ThrowIfCancellationRequested();

        // 3) Antivírus — camada OPCIONAL/plugável. Sem scanner = roda só estrutural + conteúdo ativo;
        //    a ausência de antivírus não muda o contrato acima (não inspecionado ≠ limpo).
        if (_virus is null)
        {
            if (activeContentDetected)
                return Build(fileName, size, ScanVerdict.ActiveContentDetected,
                    "conteúdo ativo detectado sob a política Flag", warnings);

            return Build(fileName, size, fullyInspected ? ScanVerdict.Clean : ScanVerdict.NotInspected,
                incompleteReason);
        }

        using var avStream = new MemoryStream(bytes, writable: false);
        ct.ThrowIfCancellationRequested();
        var (verdict, reason) = await _virus.ScanAsync(avStream, ct);
        ct.ThrowIfCancellationRequested();

        // Malicious/Error (ou outro estado não-Clean) do AV prevalece e conserva sua proveniência.
        if (verdict != ScanVerdict.Clean)
            return Build(fileName, size, verdict, reason, engine: _virus.Name);

        // AV Clean nunca promove uma decisão estrutural do FileScan a Clean, e a proveniência
        // permanece "filescan" porque foi esta camada que tomou a decisão final.
        if (activeContentDetected)
            return Build(fileName, size, ScanVerdict.ActiveContentDetected,
                "conteúdo ativo detectado sob a política Flag", warnings);

        if (!fullyInspected)
            return Build(fileName, size, ScanVerdict.NotInspected, incompleteReason);

        return Build(fileName, size, ScanVerdict.Clean, reason, engine: _virus.Name);
    }

    /// <summary>
    /// Lê a stream para memória com teto de <paramref name="maxBytes"/>+1: o +1 distingue
    /// "exatamente no máximo" de "estourou" sem jamais bufferizar o excedente.
    /// </summary>
    private static async Task<(byte[] Bytes, bool Exceeded)> ReadBoundedAsync(Stream upload, long maxBytes, CancellationToken ct)
    {
        long limit = maxBytes >= long.MaxValue ? long.MaxValue : maxBytes + 1;
        using var ms = new MemoryStream();
        var buffer = new byte[81920];
        long total = 0;

        while (total < limit)
        {
            int toRead = (int)Math.Min(buffer.Length, limit - total);
            int read = await upload.ReadAsync(buffer.AsMemory(0, toRead), ct);
            ct.ThrowIfCancellationRequested();
            if (read == 0) break;
            total += read;
            ms.Write(buffer, 0, read);
        }

        return (ms.ToArray(), total > maxBytes);
    }

    private void InspectEmbedded(byte[] content, int depth, ScanBudget budget,
        List<string> findings, List<string> incomplete)
    {
        budget.ThrowIfCancellationRequested();
        if (depth > _opt.MaxEmbeddedDepth)
        {
            incomplete.Add($"arquivo embutido — profundidade máxima {_opt.MaxEmbeddedDepth} excedida");
            return;
        }

        var dangerous = _structural.DangerousContentType(content);
        budget.ThrowIfCancellationRequested();
        if (dangerous is not null)
        {
            findings.Add($"arquivo embutido (profundidade {depth}) — tipo perigoso ('{dangerous}')");
            return;
        }

        if (ActiveContentInspector.Detect(string.Empty, content) == FileKind.Pdf)
        {
            var pdf = PdfStructuralInspector.Inspect(content, budget);
            foreach (var finding in pdf.Findings)
                findings.Add($"arquivo embutido (profundidade {depth}) — {finding}");
            foreach (var problem in pdf.Incomplete)
                incomplete.Add($"arquivo embutido (profundidade {depth}) — {problem}");

            foreach (var nested in pdf.EmbeddedFiles)
                InspectEmbedded(nested, depth + 1, budget, findings, incomplete);
            return;
        }

        var sub = ActiveContentInspector.Inspect(string.Empty, content, budget);
        foreach (var finding in sub.Findings)
            findings.Add($"arquivo embutido (profundidade {depth}) — {finding}");
        foreach (var problem in sub.Incomplete)
            incomplete.Add($"arquivo embutido (profundidade {depth}) — {problem}");
    }

    private static ScanResponse Build(string fileName, long size, ScanVerdict verdict, string? reason,
        IReadOnlyList<string>? warnings = null, string engine = "filescan")
    {
        if (verdict == ScanVerdict.Clean && warnings is { Count: > 0 })
            throw new InvalidOperationException("invariante violada: Clean não pode conter warnings");

        if (verdict == ScanVerdict.Clean)
            reason = null;

        return new(fileName, size, verdict, reason, Engine: engine,
            ScannedAtUtc: DateTime.UtcNow.ToString("O"), Warnings: warnings);
    }
}
