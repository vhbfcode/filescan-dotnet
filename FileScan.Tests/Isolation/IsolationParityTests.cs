using System.Diagnostics;
using FileScan.Scanning;
using Xunit;
using static FileScan.Tests.Isolation.IsolationHarness;

namespace FileScan.Tests.Isolation;

/// <summary>
/// Paridade InProcess x Worker: o worker roda a MESMA <see cref="FileScanService"/>; isolar não pode mudar nenhum
/// veredito, motivo ou warning de documentos que não derrubam o processo — em nenhuma das três políticas de
/// conteúdo ativo. Mais: falha ao aplicar limites do SO e sanitização do log.
/// </summary>
public class IsolationParityTests
{
    private static IEnumerable<(string Name, string File, byte[] Bytes)> Corpus()
    {
        yield return ("pdf limpo", "a.pdf", Samples.CleanPdf());
        yield return ("pdf com JS", "a.pdf", Samples.PdfWithJavaScript());
        yield return ("pdf JS hex", "a.pdf", Samples.PdfWithHexEncodedJs());
        yield return ("pdf JS em ObjStm", "a.pdf", Samples.PdfWithJavaScriptInRealObjectStream());
        yield return ("pdf com exe embutido", "a.pdf", Samples.PdfWithEmbeddedExe());
        yield return ("pdf FileSpec/EF exe", "a.pdf", Samples.PdfWithFileSpecEfExecutable());
        yield return ("pdf criptografado", "a.pdf", Samples.PdfEncrypted());
        yield return ("pdf truncado", "a.pdf", Samples.PdfTruncatedNoEof());
        yield return ("pdf PDF embutido c/ exe", "a.pdf", Samples.PdfWithEmbeddedPdfContainingExe());
        yield return ("pdf profundidade", "a.pdf", Samples.PdfWithEmbeddedDepth(5));
        yield return ("pdf ciclo /Dests", "a.pdf", Samples.PdfWithDests(2, cycle: true));
        yield return ("pdf LZW", "a.pdf", Samples.PdfWithLzwFilteredStreamHidingJs());
        yield return ("docx DDE", "a.docx", Samples.DocxWithDde());
        yield return ("csv injection", "a.csv", Samples.CsvInjection());
        yield return ("csv limpo", "a.csv", Samples.CsvCleanNegatives());
        yield return ("png com script", "a.png", Samples.PngWithScript());
        yield return ("ole2", "a.doc", Samples.Ole2WithoutVisibleMarkers());
    }

    [Theory]
    [InlineData(ActiveContentAction.Reject)]
    [InlineData(ActiveContentAction.Flag)]
    [InlineData(ActiveContentAction.Ignore)]
    public async Task WorkerAndInProcess_ProduceTheSameVerdictReasonAndWarnings(ActiveContentAction policy)
    {
        var inProcess = new FileScanService(Options(false, o => { o.Isolation = IsolationMode.InProcess; o.OnActiveContent = policy; o.AllowedExtensions = []; }));
        var worker = new FileScanService(Options(false, o => { o.OnActiveContent = policy; o.AllowedExtensions = []; }));

        var differences = new List<string>();
        foreach (var (name, file, bytes) in Corpus())
        {
            var expected = await inProcess.ScanAsync(file, bytes);
            var actual = await Scan(worker, file, bytes);
            if (expected.Verdict != actual.Verdict || expected.Reason != actual.Reason
                || expected.SizeBytes != actual.SizeBytes || expected.Engine != actual.Engine
                || !(expected.Warnings ?? []).SequenceEqual(actual.Warnings ?? []))
            {
                differences.Add($"{name} [{policy}]: InProcess={expected.Verdict}/{expected.Reason} Worker={actual.Verdict}/{actual.Reason}");
            }
        }

        Assert.True(differences.Count == 0, "isolar mudou o resultado:\n" + string.Join("\n", differences));
        Assert.Equal(0, PoolOf(worker).KilledCount); // nenhum destes documentos podia derrubar o worker
    }

    [Fact]
    public async Task FailingToApplyOsLimits_IsAnIsolationFailure_NeverClean_AndNoWorkerIsLeftRunning()
    {
        string dll = FakeWorkerPath();
        var launch = new WorkerLaunch(
            Environment.ProcessPath is { } p && Path.GetFileNameWithoutExtension(p) == "dotnet" ? p : "dotnet",
            dll,
            LimitApplier: (_, _) => throw new InvalidOperationException("limite recusado pelo SO (simulado)"));
        var pool = WorkerPool.GetOrCreate(launch, 1, 91_001 + Environment.TickCount % 1000, FileScannerOptions.DefaultWorkerMaxMemoryBytes);
        var request = new WorkerRequest("x.pdf", 1, WorkerContentOptions.From(new FileScannerOptions()));

        var result = await Bounded(pool.RunAsync(request, [1], TimeSpan.FromSeconds(30), CancellationToken.None), "limites do SO");

        Assert.Null(result.Response);
        Assert.Contains("limites do SO", result.Failure);
        Assert.Empty(pool.LivePids);
        Assert.Equal(0, pool.StartedCount);
    }

    [Fact]
    public async Task IsolationLog_NeutralizesControlCharactersFromHostileFileNames()
    {
        var events = new List<string>();
        var service = new FileScanService(Options(true, events: events));

        var response = await Scan(service, "die-\r\n[FORGED] linha falsa\r\n.pdf", Samples.CleanPdf());

        AssertVerdict(ScanVerdict.NotInspected, response, "worker morto por nome hostil");
        Assert.NotEmpty(events);
        Assert.All(events, e => Assert.DoesNotContain('\n', e));
        Assert.All(events, e => Assert.DoesNotContain('\r', e));
    }
}
