using FileScan.Scanning;
using Xunit;

namespace FileScan.Tests;

/// <summary>
/// Contrato de consumo como BIBLIOTECA (FileScan.Core): new + ScanAsync, sem DI, sem API,
/// sem ClamAV. É o modo de uso dos projetos que referenciam o Core diretamente.
/// </summary>
public class FileScanServiceLibraryTests
{
    private static FileScanService Make(FileScannerOptions? options = null)
        => new(options ?? new FileScannerOptions());

    [Fact]
    public async Task CleanPdf_StandaloneUsage_ReturnsClean()
    {
        var result = await Make().ScanAsync("contrato.pdf", Samples.CleanPdf());
        Assert.Equal(ScanVerdict.Clean, result.Verdict);
        Assert.Equal("filescan", result.Engine); // sem IVirusScanner plugado
    }

    [Fact]
    public async Task PdfWithJavaScript_StandaloneUsage_IsRejected()
    {
        var result = await Make().ScanAsync("malicioso.pdf", Samples.PdfWithJavaScript());
        Assert.Equal(ScanVerdict.Rejected, result.Verdict);
        Assert.Contains("JavaScript", result.Reason);
    }

    [Fact]
    public async Task TwoInstances_DifferentLimits_DoNotInterfere()
    {
        // Opções são POR INSTÂNCIA (sem estado global): um limite apertado numa instância
        // não pode vazar para a outra no mesmo processo.
        var pdf = Samples.CleanPdf();
        var strict = Make(new FileScannerOptions { MaxFileSizeBytes = 10 }); // menor que o sample
        var normal = Make();

        Assert.Equal(ScanVerdict.Rejected, (await strict.ScanAsync("x.pdf", pdf)).Verdict);
        Assert.Equal(ScanVerdict.Clean, (await normal.ScanAsync("x.pdf", pdf)).Verdict);
    }

    [Fact]
    public async Task OptionsMutatedAfterConstruction_CannotDisableInspectionOrOverflowBudget()
    {
        var options = new FileScannerOptions();
        var scanner = Make(options);
        var pdf = Samples.PdfWithJavaScriptOnlyInsideFlateStream();

        Assert.Equal(ScanVerdict.Rejected, (await scanner.ScanAsync("x.pdf", pdf)).Verdict);

        options.MaxDecompressedBytesPerStream = long.MaxValue;
        options.MaxTotalDecompressedBytes = long.MaxValue;
        options.OnActiveContent = ActiveContentAction.Ignore;
        options.AllowedExtensions = ["txt"];

        var result = await scanner.ScanAsync("x.pdf", pdf);
        Assert.Equal(ScanVerdict.Rejected, result.Verdict);
        Assert.Contains("JavaScript", result.Reason);
    }

    [Fact]
    public async Task FlagPolicy_ReturnsNonPersistableVerdictWithWarnings()
    {
        var svc = Make(new FileScannerOptions { OnActiveContent = ActiveContentAction.Flag });
        var result = await svc.ScanAsync("malicioso.pdf", Samples.PdfWithJavaScript());
        Assert.Equal(ScanVerdict.ActiveContentDetected, result.Verdict);
        Assert.NotNull(result.Warnings);
        Assert.NotEmpty(result.Warnings);
    }
}
