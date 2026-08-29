namespace FileScan.Scanning;

/// <summary>
/// Camada de antivírus plugável do <see cref="FileScanService"/>. A biblioteca não depende de
/// nenhum motor: quem hospeda decide (a API deste repo pluga o ClamAV via nClam; um consumidor
/// da biblioteca pode não plugar nada — aí rodam só as camadas estrutural + conteúdo ativo).
/// </summary>
public interface IVirusScanner
{
    /// <summary>Nome do motor, reportado em <see cref="ScanResponse.Engine"/> (ex.: "clamav").</summary>
    string Name { get; }

    /// <summary>
    /// Escaneia o conteúdo. Contrato fail-closed: problema de comunicação/motor deve virar
    /// <see cref="ScanVerdict.Error"/> (nunca Clean).
    /// </summary>
    Task<(ScanVerdict Verdict, string? Reason)> ScanAsync(Stream content, CancellationToken ct);
}
