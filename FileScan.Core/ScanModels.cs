using System.Text.Json.Serialization;

namespace FileScan.Scanning;

/// <summary>Veredito do validador.</summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum ScanVerdict
{
    /// <summary>
    /// Passou na validação estrutural, a inspeção de conteúdo ativo terminou sem achado e o
    /// antivírus (quando plugado) não encontrou ameaça.
    /// ⚠️ Escopo da garantia "inspeção integral ⇒ Clean": vale para <b>PDF e OOXML</b>, cujos
    /// inspetores sinalizam <see cref="NotInspected"/> quando algum trecho não pôde ser lido.
    /// Para OLE2 (doc/xls legado), imagens, CSV e texto o motor é heurística best-effort de
    /// varredura de bytes: <c>Clean</c> nesses formatos significa "nenhum marcador casou",
    /// NÃO "inspeção estrutural integral" (macro OLE2 ofuscada/comprimida pode evadir).
    /// </summary>
    Clean,

    /// <summary>Antivírus encontrou malware.</summary>
    Malicious,

    /// <summary>Reprovado na validação estrutural (tipo/extensão/tamanho) — nem chegou ao antivírus.</summary>
    Rejected,

    /// <summary>Não foi possível escanear (ex.: ClamAV indisponível). O chamador deve falhar fechado.</summary>
    Error,

    /// <summary>
    /// A inspeção estrutural/de conteúdo ativo NÃO foi concluída integralmente: filtro de stream
    /// não suportado, PDF criptografado, estrutura inválida/truncada ou limite de descompressão
    /// interrompido. NÃO significa "benigno" — ausência de inspeção nunca vira aceitação; o
    /// chamador fail-closed não deve persistir. <see cref="ScanResponse.Reason"/> lista os trechos
    /// não inspecionados.
    /// </summary>
    NotInspected,

    /// <summary>
    /// Conteúdo ativo foi encontrado sob a política <see cref="ActiveContentAction.Flag"/>.
    /// O arquivo não é persistível; <see cref="ScanResponse.Warnings"/> preserva os achados para
    /// telemetria. Esse estado nunca é promovido a <see cref="Clean"/> por um antivírus limpo.
    /// </summary>
    ActiveContentDetected
}

/// <summary>
/// Resultado da inspeção de conteúdo ativo: o que foi ENCONTRADO (<see cref="Findings"/>) e o que
/// NÃO PÔDE ser inspecionado (<see cref="Incomplete"/>). Distinção central do contrato: um arquivo
/// só é considerado limpo quando <c>Findings</c> está vazio E a inspeção foi integral
/// (<c>Incomplete</c> vazio) — trecho ilegível nunca é tratado como benigno.
/// ⚠️ Só os inspetores de <b>PDF e OOXML</b> alimentam <c>Incomplete</c>; nos demais formatos
/// (OLE2/imagem/CSV/texto) a varredura é best-effort e <c>Incomplete</c> sai vazio por construção —
/// ver o escopo documentado em <see cref="ScanVerdict.Clean"/>.
/// </summary>
public sealed record InspectionResult(IReadOnlyList<string> Findings, IReadOnlyList<string> Incomplete)
{
    /// <summary>Resultado vazio: nada encontrado, inspeção integral.</summary>
    public static InspectionResult Empty { get; } = new([], []);

    /// <summary>true quando a inspeção cobriu o arquivo inteiro dentro da política suportada.</summary>
    public bool FullyInspected => Incomplete.Count == 0;
}

/// <summary>Resposta do endpoint <c>POST /scan</c>.</summary>
/// <remarks>
/// Regra para o chamador: só persistir o arquivo se HTTP 200 E Verdict == Clean.
/// Qualquer outra combinação (Malicious, Rejected, ActiveContentDetected, NotInspected, ou
/// HTTP 503/Error) = não persistir. <c>Clean</c> sempre tem <see cref="Warnings"/> nulo ou vazio.
/// </remarks>
public sealed record ScanResponse(
    string FileName,
    long SizeBytes,
    ScanVerdict Verdict,
    string? Reason,
    string Engine,
    string ScannedAtUtc,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    IReadOnlyList<string>? Warnings = null);
