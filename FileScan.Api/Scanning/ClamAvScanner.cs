using nClam;

namespace FileScan.Scanning;

/// <summary>
/// Wrapper sobre o nClam. Falha fechado: qualquer problema de comunicação vira <see cref="ScanVerdict.Error"/>.
/// </summary>
public sealed class ClamAvScanner(IClamClient client, ILogger<ClamAvScanner> logger)
{
    public async Task<(ScanVerdict Verdict, string? Reason)> ScanAsync(Stream content, CancellationToken ct)
    {
        try
        {
            var result = await client.SendAndScanFileAsync(content, ct);

            return result.Result switch
            {
                ClamScanResults.Clean => (ScanVerdict.Clean, null),
                ClamScanResults.VirusDetected => (
                    ScanVerdict.Malicious,
                    result.InfectedFiles is { Count: > 0 }
                        ? string.Join(", ", result.InfectedFiles.Select(f => f.VirusName?.Trim()))
                        : "malware detectado"),
                _ => (ScanVerdict.Error, result.RawResult)
            };
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Falha ao comunicar com o ClamAV ({Server}:{Port})", client.Server, client.Port);
            return (ScanVerdict.Error, "ClamAV indisponível");
        }
    }

    /// <summary>Ping para readiness. Não lança — retorna false se o ClamAV não responder.</summary>
    public Task<bool> PingAsync(CancellationToken ct = default) => client.TryPingAsync(ct);
}
