namespace FileScan.Scanning;

/// <summary>
/// Limites de descompressão aplicados pelos inspetores (guarda anti-DoS de "zip bomb").
/// Definido uma única vez no startup a partir de <see cref="FileScanOptions"/>; somente leitura em runtime.
/// </summary>
internal static class ScanLimits
{
    /// <summary>Máximo de bytes descomprimidos lidos por stream/anexo. Default 16 MB.</summary>
    public static long MaxDecompressedBytesPerStream { get; set; } = 16 * 1024 * 1024;
}
