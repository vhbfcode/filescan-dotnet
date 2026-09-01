using FileScan.Scanning;
using Xunit;

namespace FileScan.Tests;

/// <summary>
/// Contrato fail-closed da rodada 0.1.1 → 0.2.0:
/// - Frente A: Clean SÓ quando a inspeção terminou integralmente; inspeção incompleta = NotInspected.
/// - Frente C: /Embedded#46ile (escape #XX) não evade a inspeção recursiva de anexos.
/// - Frente D: leitura limitada + rejeição de tamanho declarado inválido/divergente.
/// </summary>
public class FailClosedContractTests
{
    private static FileScanService Make(FileScannerOptions? options = null)
        => new(options ?? new FileScannerOptions());

    // --- Frente A: veredito distinto para inspeção não concluída ---

    [Fact]
    public async Task UnsupportedFilter_HidingJs_IsNotClean()
    {
        // Um /JS dentro de um stream LZW não pode "escapar como Clean" (era o fail-open da B2).
        var r = await Make().ScanAsync("x.pdf", Samples.PdfWithLzwFilteredStreamHidingJs());
        Assert.Equal(ScanVerdict.NotInspected, r.Verdict);
        Assert.Contains("não", r.Reason); // motivo lista o trecho não inspecionado
    }

    [Fact]
    public async Task EncryptedPdf_IsNotInspected()
        => Assert.Equal(ScanVerdict.NotInspected,
            (await Make().ScanAsync("x.pdf", Samples.PdfEncrypted())).Verdict);

    [Fact]
    public async Task TruncatedPdf_NoEof_IsNotInspected()
        => Assert.Equal(ScanVerdict.NotInspected,
            (await Make().ScanAsync("x.pdf", Samples.PdfTruncatedNoEof())).Verdict);

    [Fact]
    public async Task IncrementalUpdateTruncatedAfterIntermediateEof_IsNotInspected()
        // F2: %%EOF intermediário não conta como fim de arquivo íntegro.
        => Assert.Equal(ScanVerdict.NotInspected,
            (await Make().ScanAsync("x.pdf", Samples.PdfTruncatedAfterIntermediateEof())).Verdict);

    [Fact]
    public async Task DecompressionCapExceeded_IsNotInspected()
    {
        var svc = Make(new FileScannerOptions { MaxDecompressedBytesPerStream = 1024 });
        var r = await svc.ScanAsync("x.pdf", Samples.PdfWithLargeFlateStream(64 * 1024));
        Assert.Equal(ScanVerdict.NotInspected, r.Verdict);
    }

    [Fact]
    public async Task CorruptFlateStream_IsNotInspected()
        // Corpo com /Filter declarado que não infla (o antigo caminho silencioso do FP relatado).
        => Assert.Equal(ScanVerdict.NotInspected,
            (await Make().ScanAsync("x.pdf", Samples.PdfWithCompressedNoiseLookingLikeJs())).Verdict);

    [Fact]
    public async Task FlagPolicy_DoesNotPromoteIncompleteInspectionToClean()
    {
        // Mesmo sob Flag (política permissiva), inspeção incompleta nunca vira Clean.
        var svc = Make(new FileScannerOptions { OnActiveContent = ActiveContentAction.Flag });
        var r = await svc.ScanAsync("x.pdf", Samples.PdfWithLzwFilteredStreamHidingJs());
        Assert.Equal(ScanVerdict.NotInspected, r.Verdict);
    }

    // --- Frente B1 no nível do serviço: PDF legítimo com texto inerte é Clean ---

    [Fact]
    public async Task MarkerOnlyInLiteralString_IsClean()
        => Assert.Equal(ScanVerdict.Clean,
            (await Make().ScanAsync("x.pdf", Samples.PdfWithMarkerOnlyInLiteralString())).Verdict);

    [Fact]
    public async Task MarkerOnlyInComment_IsClean()
        => Assert.Equal(ScanVerdict.Clean,
            (await Make().ScanAsync("x.pdf", Samples.PdfWithMarkerOnlyInComment())).Verdict);

    [Fact]
    public async Task MarkerInPageText_Uncompressed_IsClean()
        => Assert.Equal(ScanVerdict.Clean,
            (await Make().ScanAsync("x.pdf", Samples.PdfWithMarkerInPageTextUncompressed())).Verdict);

    [Fact]
    public async Task MarkerInPageText_Flate_IsClean()
        => Assert.Equal(ScanVerdict.Clean,
            (await Make().ScanAsync("x.pdf", Samples.PdfWithMarkerInPageTextFlate())).Verdict);

    [Fact]
    public async Task EndstreamBytesInsideMeasuredBody_IsClean()
        => Assert.Equal(ScanVerdict.Clean,
            (await Make().ScanAsync("x.pdf", Samples.PdfWithEndstreamBytesInsideMeasuredStream())).Verdict);

    [Fact]
    public async Task JsHiddenAfterDeclaredLength_IsRejected()
        => Assert.Equal(ScanVerdict.Rejected,
            (await Make().ScanAsync("x.pdf", Samples.PdfHidingJsAfterDeclaredLength())).Verdict);

    // --- Frente C: escape #XX no extrator de anexos ---

    [Fact]
    public async Task HexEscapedEmbeddedFile_WithExe_IsRejected()
    {
        var r = await Make().ScanAsync("attach.pdf", Samples.PdfWithHexEscapedEmbeddedFileExe());
        Assert.Equal(ScanVerdict.Rejected, r.Verdict);
        Assert.Contains("tipo perigoso", r.Reason);
    }

    [Fact]
    public async Task PlainEmbeddedFile_WithExe_StillRejected()
        // Regressão: a forma literal continua detectada após a mudança do matcher.
        => Assert.Equal(ScanVerdict.Rejected,
            (await Make().ScanAsync("attach.pdf", Samples.PdfWithEmbeddedExe())).Verdict);

    // --- Frente D: leitura limitada + tamanho declarado não confiável ---

    [Fact]
    public async Task NegativeDeclaredSize_IsRejected()
    {
        using var ms = new MemoryStream(Samples.CleanPdf());
        var r = await Make().ScanAsync("x.pdf", ms, declaredSize: -1, default);
        Assert.Equal(ScanVerdict.Rejected, r.Verdict);
    }

    [Fact]
    public async Task DeclaredSmall_RealHuge_IsRejected_WithoutBufferingEverything()
    {
        // Atacante declara 500 KB e envia 50 MB: a leitura corta em máximo+1 — nunca bufferiza o resto.
        var opt = new FileScannerOptions { MaxFileSizeBytes = 1024 * 1024 };
        var counting = new CountingZeroStream(totalLength: 50L * 1024 * 1024);

        var r = await Make(opt).ScanAsync("x.bin", counting, declaredSize: 500 * 1024, default);

        Assert.Equal(ScanVerdict.Rejected, r.Verdict);
        Assert.True(counting.BytesServed <= opt.MaxFileSizeBytes + 1,
            $"leu {counting.BytesServed} bytes; o corte deveria ocorrer em {opt.MaxFileSizeBytes + 1}");
    }

    [Fact]
    public async Task DeclaredBigger_RealSmaller_SizeMismatch_IsRejected()
    {
        // Antes: declarado 10 MB / real 100 B passava como Clean sem detectar a divergência.
        var content = Samples.CleanPdf();
        using var ms = new MemoryStream(content);
        var r = await Make().ScanAsync("x.pdf", ms, declaredSize: content.Length + 1000, default);
        Assert.Equal(ScanVerdict.Rejected, r.Verdict);
        Assert.Contains("diverge", r.Reason);
    }

    [Fact]
    public async Task DeclaredSmaller_RealBigger_UnderMax_SizeMismatch_IsRejected()
    {
        var content = Samples.CleanPdf();
        using var ms = new MemoryStream(content);
        var r = await Make().ScanAsync("x.pdf", ms, declaredSize: content.Length - 5, default);
        Assert.Equal(ScanVerdict.Rejected, r.Verdict);
        Assert.Contains("diverge", r.Reason);
    }

    [Fact]
    public async Task ExactlyAtMax_MatchingDeclared_IsNotRejectedBySize()
    {
        // Fronteira: arquivo exatamente no máximo, declarado corretamente, não é barrado por tamanho.
        var pdf = Samples.CleanPdf();
        var opt = new FileScannerOptions { MaxFileSizeBytes = pdf.Length };
        var r = await Make(opt).ScanAsync("x.pdf", pdf);
        Assert.Equal(ScanVerdict.Clean, r.Verdict);
    }

    /// <summary>Stream sintética de zeros que conta quantos bytes foram efetivamente lidos.</summary>
    private sealed class CountingZeroStream(long totalLength) : Stream
    {
        private long _pos;
        public long BytesServed { get; private set; }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => totalLength;
        public override long Position { get => _pos; set => throw new NotSupportedException(); }

        public override int Read(byte[] buffer, int offset, int count)
        {
            int n = (int)Math.Min(count, totalLength - _pos);
            if (n <= 0) return 0;
            Array.Clear(buffer, offset, n);
            _pos += n;
            BytesServed += n;
            return n;
        }

        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
