using System.Text.Json.Serialization;

namespace FileScan.Scanning;

/// <summary>Veredito do validador.</summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum ScanVerdict
{
    /// <summary>Passou na validação estrutural e o antivírus não encontrou ameaça.</summary>
    Clean,

    /// <summary>Antivírus encontrou malware.</summary>
    Malicious,

    /// <summary>Reprovado na validação estrutural (tipo/extensão/tamanho) — nem chegou ao antivírus.</summary>
    Rejected,

    /// <summary>Não foi possível escanear (ex.: ClamAV indisponível). O chamador deve falhar fechado.</summary>
    Error
}

/// <summary>Resposta do endpoint <c>POST /scan</c>.</summary>
/// <remarks>
/// Regra para o chamador: só persistir o arquivo se HTTP 200 E Verdict == Clean.
/// Qualquer outra combinação (Malicious, Rejected, ou HTTP 503/Error) = não persistir.
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
