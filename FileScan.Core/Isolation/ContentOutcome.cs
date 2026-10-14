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
    /// Confere as invariantes que um outcome HONESTO sempre cumpre, inclusive as LIGADAS À POLÍTICA: o worker é
    /// código nosso, mas a resposta é entrada de outro processo; o que não fechar vira falha de isolamento,
    /// não decisão. Sob <see cref="ActiveContentAction.Reject"/> o estágio nunca devolve "conteúdo ativo
    /// detectado" (devolve Rejected terminal); sob <see cref="ActiveContentAction.Ignore"/> a inspeção é pulada,
    /// então jamais é integral e nada é detectado; terminal Rejected só existe sob Reject.
    /// </summary>
    public string? ValidationProblem(long expectedSize, ActiveContentAction policy)
    {
        if (Terminal is { } terminal)
        {
            if (policy != ActiveContentAction.Reject)
                return $"veredito terminal do worker incompatível com a política {policy}";
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
        if (policy == ActiveContentAction.Reject && ActiveContentDetected)
            return "resposta do worker incompatível com a política Reject (conteúdo ativo sem rejeição)";
        if (policy == ActiveContentAction.Ignore && (FullyInspected || ActiveContentDetected))
            return "resposta do worker incompatível com a política Ignore (inspeção pulada não pode ser integral)";
        return null;
    }
}
