namespace FileScan.Scanning;

/// <summary>
/// API pública da inspeção PDF. A implementação usa um parser estrutural estrito,
/// filtros limitados e propagação fail-closed; nenhum fallback textual pode concluir Clean.
/// </summary>
public static class PdfActiveContentInspector
{
    public static InspectionResult Inspect(byte[] content,
        long maxDecompressedBytesPerStream = FileScannerOptions.DefaultMaxDecompressedBytesPerStream)
    {
        var options = new FileScannerOptions
        {
            MaxDecompressedBytesPerStream = maxDecompressedBytesPerStream,
            MaxTotalDecompressedBytes = Math.Max(
                FileScannerOptions.DefaultMaxTotalDecompressedBytes,
                maxDecompressedBytesPerStream),
        };
        options.Validate();
        return Inspect(content, new ScanBudget(options));
    }

    internal static InspectionResult Inspect(byte[] content, ScanBudget budget)
    {
        var result = PdfStructuralInspector.Inspect(content, budget);
        return new(result.Findings, result.Incomplete);
    }
}
