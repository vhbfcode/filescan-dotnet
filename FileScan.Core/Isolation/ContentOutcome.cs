namespace FileScan.Scanning;

/// <summary>
/// Resultado do estágio de conteúdo ativo (estágio 2 do <see cref="FileScanService"/>), a parte que
/// abre o PDF e que, com <see cref="IsolationMode.Worker"/>, roda no processo filho e atravessa o
/// protocolo como JSON. O antivírus (estágio 3) NUNCA cruza o processo: o hospedeiro o aplica depois.
/// Só o hospedeiro decide <see cref="ScanVerdict.Clean"/>, a partir de um outcome validado.
/// </summary>
internal sealed record ContentOutcome(
    ScanResponse? Terminal,
    bool ActiveContentDetected,
    IReadOnlyList<string>? Warnings,
    bool FullyInspected,
    string? IncompleteReason,
    long Size)
{
    /// <summary>Decisão final já tomada pelo estágio (hoje: só <see cref="ScanVerdict.Rejected"/>).</summary>
    public static ContentOutcome Finished(ScanResponse response) =>
        new(response, false, null, false, null, response.SizeBytes);

    /// <summary>Falha de isolamento: o conteúdo não foi inspecionado. Nunca vira Clean.</summary>
    public static ContentOutcome Failed(string reason, long size) =>
        new(null, false, null, false, "inspeção isolada não concluída: " + reason, size);

    /// <summary>
    /// Confere as invariantes que um outcome HONESTO sempre cumpre. O worker é código nosso, mas a
    /// resposta é entrada de outro processo: o que não fechar vira falha de isolamento, não decisão.
    /// </summary>
    public string? ValidationProblem(long expectedSize)
    {
        if (Terminal is { } terminal)
        {
            if (terminal.Verdict != ScanVerdict.Rejected)
                return $"veredito terminal inesperado do worker ({terminal.Verdict})";
            if (string.IsNullOrEmpty(terminal.Reason))
                return "veredito terminal do worker sem motivo";
            return null;
        }

        if (Size != expectedSize)
            return "tamanho divergente na resposta do worker";
        if (FullyInspected != (IncompleteReason is null))
            return "resposta do worker incoerente (inspeção integral x motivo de incompletude)";
        if (ActiveContentDetected != (Warnings is { Count: > 0 }))
            return "resposta do worker incoerente (conteúdo ativo x warnings)";
        return null;
    }
}
