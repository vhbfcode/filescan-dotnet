using FileScan.Scanning;
using UglyToad.PdfPig;
using UglyToad.PdfPig.Core;
using UglyToad.PdfPig.Tokens;
using Xunit;

namespace FileScan.Tests;

/// <summary>
/// Corpus nominal da 0.2.0. Cada nome corresponde a uma invariável/contraexemplo do plano
/// CORRECOES-0.2.0-ADVERSARIAL; não substituir por uma mera contagem agregada.
/// </summary>
public class Adversarial020ContractTests
{
    private static FileScanService Make(FileScannerOptions? options = null, IVirusScanner? virus = null) =>
        new(options ?? new FileScannerOptions(), virusScanner: virus);

    [Fact]
    public async Task IgnorePolicy_UnsupportedFilter_IsNotInspected()
    {
        var result = await Make(new() { OnActiveContent = ActiveContentAction.Ignore })
            .ScanAsync("x.pdf", Samples.PdfWithLzwFilteredStreamHidingJs());
        Assert.Equal(ScanVerdict.NotInspected, result.Verdict);
        Assert.Null(result.Warnings);
    }

    [Fact]
    public async Task FlagPolicy_RealJavaScript_IsActiveContentDetected()
    {
        var result = await Make(new() { OnActiveContent = ActiveContentAction.Flag })
            .ScanAsync("x.pdf", Samples.PdfWithJavaScript());
        Assert.Equal(ScanVerdict.ActiveContentDetected, result.Verdict);
        Assert.NotEmpty(result.Warnings!);
    }

    [Fact]
    public async Task DictionaryLiteralContainingObj_DoesNotHideFilterOrJavascript()
        => Assert.Equal(ScanVerdict.Rejected,
            (await Make().ScanAsync("x.pdf",
                Samples.PdfWithDictionaryStringContainingObjAndCompressedJs())).Verdict);

    [Fact]
    public async Task LiteralStreamKeyword_DoesNotConsumeRealCompressedStream()
        => Assert.Equal(ScanVerdict.Rejected,
            (await Make().ScanAsync("x.pdf",
                Samples.PdfWithLiteralStreamKeywordBeforeCompressedJs())).Verdict);

    [Fact]
    public async Task RealObjectStreamWithType2Xref_IsResolvedAndRejected()
    {
        byte[] pdf = Samples.PdfWithJavaScriptInRealObjectStream();
        using var document = PdfDocument.Open(pdf, new ParsingOptions { UseLenientParsing = false });
        ObjectToken compressedObject = document.Structure.GetObject(new IndirectReference(7, 0));

        Assert.IsType<DictionaryToken>(compressedObject.Data);
        Assert.Equal(ScanVerdict.Rejected, (await Make().ScanAsync("x.pdf", pdf)).Verdict);
    }

    [Fact]
    public async Task ShortIncrementalUpdateWithoutFinalEof_IsNotInspected()
        => Assert.Equal(ScanVerdict.NotInspected,
            (await Make().ScanAsync("x.pdf", Samples.PdfWithShortTruncatedIncrementalUpdate())).Verdict);

    [Fact]
    public async Task BytesAfterFinalEof_AreNotInspected()
        => Assert.Equal(ScanVerdict.NotInspected,
            (await Make().ScanAsync("x.pdf", Samples.PdfWithBytesAfterFinalEof())).Verdict);

    [Fact]
    public async Task UnterminatedLiteralContainingOnlyEof_IsNotInspected()
        => Assert.Equal(ScanVerdict.NotInspected,
            (await Make().ScanAsync("x.pdf", Samples.PdfWithUnterminatedLiteralContainingOnlyEof())).Verdict);

    [Fact]
    public async Task ExecutableIn51stEmbeddedFile_IsNeverClean()
    {
        var result = await Make().ScanAsync("x.pdf", Samples.PdfWithExecutableIn51stEmbeddedFile());
        Assert.NotEqual(ScanVerdict.Clean, result.Verdict);
        Assert.Equal(ScanVerdict.NotInspected, result.Verdict);
    }

    [Fact]
    public async Task NestedCompressedPdfWithExecutable_IsRejected()
        => Assert.Equal(ScanVerdict.Rejected,
            (await Make().ScanAsync("x.pdf", Samples.PdfWithEmbeddedPdfContainingExe())).Verdict);

    [Fact]
    public async Task FileSpecEfWithoutEmbeddedFileType_IsRejected()
        => Assert.Equal(ScanVerdict.Rejected,
            (await Make().ScanAsync("x.pdf", Samples.PdfWithFileSpecEfExecutable())).Verdict);

    [Fact]
    public async Task FileSpecAndStreamTypesOptional_CompressedExecutableIsRejected()
        => Assert.Equal(ScanVerdict.Rejected,
            (await Make().ScanAsync("x.pdf", Samples.PdfWithFileSpecEfExecutable(
                declareFileSpecType: false, compressed: true))).Verdict);

    [Fact]
    public async Task FileSpecEfMissingReference_IsNotInspected()
        => Assert.Equal(ScanVerdict.NotInspected,
            (await Make().ScanAsync("x.pdf", Samples.PdfWithFileSpecEfMissingReference())).Verdict);

    [Fact]
    public async Task FileSpecEfNonStream_IsNotInspected()
        => Assert.Equal(ScanVerdict.NotInspected,
            (await Make().ScanAsync("x.pdf", Samples.PdfWithFileSpecEfNonStream())).Verdict);

    [Fact]
    public async Task IndirectEfDictionaryAndUfKey_ExecutableIsRejected()
        => Assert.Equal(ScanVerdict.Rejected,
            (await Make().ScanAsync("x.pdf", Samples.PdfWithIndirectEfDictionaryExecutable())).Verdict);

    [Fact]
    public async Task CyclicEfReference_IsNotInspected()
        => Assert.Equal(ScanVerdict.NotInspected,
            (await Make().ScanAsync("x.pdf", Samples.PdfWithCyclicEfReference())).Verdict);

    [Fact]
    public async Task UnrelatedEfDictionaryOutsideFileSpec_IsNotTreatedAsAttachment()
        => Assert.Equal(ScanVerdict.Clean,
            (await Make().ScanAsync("x.pdf", Samples.PdfWithUnrelatedCatalogEfKey())).Verdict);

    [Fact]
    public async Task UnrelatedEfScalarOutsideFileSpec_IsNotTreatedAsAttachment()
        => Assert.Equal(ScanVerdict.Clean,
            (await Make().ScanAsync("x.pdf", Samples.PdfWithUnrelatedCatalogEfKey(scalar: true))).Verdict);

    [Fact]
    public async Task EmbeddedFilesNameTreeScalarValue_IsNotInspected()
        => Assert.Equal(ScanVerdict.NotInspected,
            (await Make().ScanAsync("x.pdf", Samples.PdfWithEmbeddedFilesScalarValue())).Verdict);

    [Fact]
    public async Task EmbeddedFilesNameTreeDirectStream_IsNotInspected()
        => Assert.Equal(ScanVerdict.NotInspected,
            (await Make().ScanAsync("x.pdf", Samples.PdfWithEmbeddedFilesDirectStream())).Verdict);

    [Fact]
    public async Task EmbeddedFilesNameTreeExternalPathString_CanBeClean()
        => Assert.Equal(ScanVerdict.Clean,
            (await Make().ScanAsync("x.pdf", Samples.PdfWithEmbeddedFilesExternalPathString())).Verdict);

    [Fact]
    public async Task EmbeddedFilesNameTreeNonStringKey_IsNotInspected()
        => Assert.Equal(ScanVerdict.NotInspected,
            (await Make().ScanAsync("x.pdf", Samples.PdfWithEmbeddedFilesNonStringKey())).Verdict);

    [Fact]
    public async Task EmbeddedFilesNameTreeOutOfOrderKeys_IsNotInspected()
        => Assert.Equal(ScanVerdict.NotInspected,
            (await Make().ScanAsync("x.pdf", Samples.PdfWithEmbeddedFilesOutOfOrderKeys())).Verdict);

    [Fact]
    public async Task EmbeddedFilesNameTreeInvalidLimits_IsNotInspected()
        => Assert.Equal(ScanVerdict.NotInspected,
            (await Make().ScanAsync("x.pdf", Samples.PdfWithEmbeddedFilesInvalidLimits())).Verdict);

    [Fact]
    public async Task EmbeddedFilesNameTreeRootNamesWithLimits_IsNotInspected()
        => Assert.Equal(ScanVerdict.NotInspected,
            (await Make().ScanAsync("x.pdf", Samples.PdfWithEmbeddedFilesRootNamesAndLimits())).Verdict);

    [Fact]
    public async Task EmbeddedFilesNameTreeRootKidsWithLimits_IsNotInspected()
        => Assert.Equal(ScanVerdict.NotInspected,
            (await Make().ScanAsync("x.pdf", Samples.PdfWithEmbeddedFilesRootKidsAndLimits())).Verdict);

    [Fact]
    public async Task EmbeddedFilesNameTreeHexStringKey_CanBeClean()
        => Assert.Equal(ScanVerdict.Clean,
            (await Make().ScanAsync("x.pdf", Samples.PdfWithEmbeddedFilesHexStringKey())).Verdict);

    [Fact]
    public async Task EmbeddedFilesNameTreeHexStringKeyAndLimits_CanBeClean()
        => Assert.Equal(ScanVerdict.Clean,
            (await Make().ScanAsync("x.pdf", Samples.PdfWithEmbeddedFilesHexStringKeyAndLimits())).Verdict);

    [Fact]
    public async Task EmbeddedFilesNameTreeMixedLiteralAndHexKeys_CanBeClean()
        => Assert.Equal(ScanVerdict.Clean,
            (await Make().ScanAsync("x.pdf", Samples.PdfWithEmbeddedFilesMixedLiteralAndHexKeys())).Verdict);

    [Fact]
    public async Task EmbeddedFilesNameTreeMixedLiteralAndHexDuplicate_IsNotInspected()
        => Assert.Equal(ScanVerdict.NotInspected,
            (await Make().ScanAsync("x.pdf", Samples.PdfWithEmbeddedFilesMixedDuplicateKeys())).Verdict);

    [Fact]
    public async Task EmbeddedFilesNameTreeChildWithoutLimits_IsNotInspected()
        => Assert.Equal(ScanVerdict.NotInspected,
            (await Make().ScanAsync("x.pdf", Samples.PdfWithEmbeddedFilesChildMissingLimits())).Verdict);

    [Fact]
    public async Task EmbeddedFilesNameTreeDirectKid_IsNotInspected()
        => Assert.Equal(ScanVerdict.NotInspected,
            (await Make().ScanAsync("x.pdf", Samples.PdfWithEmbeddedFilesDirectKid())).Verdict);

    [Fact]
    public async Task EmbeddedFilesNameTreeIntermediateNodeWithoutLimits_IsNotInspected()
        => Assert.Equal(ScanVerdict.NotInspected,
            (await Make().ScanAsync("x.pdf", Samples.PdfWithEmbeddedFilesIntermediateNodeMissingLimits())).Verdict);

    [Fact]
    public async Task EmbeddedFilesNameTreeValidIndirectKid_CanBeClean()
        => Assert.Equal(ScanVerdict.Clean,
            (await Make().ScanAsync("x.pdf", Samples.PdfWithEmbeddedFilesValidIndirectKid())).Verdict);

    [Fact]
    public async Task EmbeddedFilesKeyOutsideCatalogNames_IsIgnored()
        => Assert.Equal(ScanVerdict.Clean,
            (await Make().ScanAsync("x.pdf", Samples.PdfWithUnrelatedEmbeddedFilesKey())).Verdict);

    [Fact]
    public async Task FileSpecFsOutsideFileAttachment_IsNotTreatedAsAttachment()
        => Assert.Equal(ScanVerdict.Clean,
            (await Make().ScanAsync("x.pdf", Samples.PdfWithUnrelatedCustomFsKey())).Verdict);

    [Fact]
    public async Task AssociatedFileWithoutOptionalTypes_IsRejected()
        => Assert.Equal(ScanVerdict.Rejected,
            (await Make().ScanAsync("x.pdf", Samples.PdfWithAssociatedFileExecutable())).Verdict);

    [Fact]
    public async Task FileAttachmentFsWithoutOptionalTypes_IsRejected()
        => Assert.Equal(ScanVerdict.Rejected,
            (await Make().ScanAsync("x.pdf", Samples.PdfWithFileAttachmentExecutable())).Verdict);

    [Fact]
    public async Task IncompleteInspectionWithCleanAntivirus_IsAttributedToFileScan()
    {
        var result = await Make(virus: new StubVirus(ScanVerdict.Clean))
            .ScanAsync("x.pdf", Samples.PdfWithLzwFilteredStreamHidingJs());
        Assert.Equal(ScanVerdict.NotInspected, result.Verdict);
        Assert.Equal("filescan", result.Engine);
    }

    [Fact]
    public async Task IndirectLengthStream_IsStructurallyInspected()
        => Assert.Equal(ScanVerdict.Clean,
            (await Make().ScanAsync("x.pdf", Samples.PdfWithIndirectLengthStream())).Verdict);

    [Fact]
    public async Task UnsupportedPredictor_IsNotInspected()
        => Assert.Equal(ScanVerdict.NotInspected,
            (await Make().ScanAsync("x.pdf", Samples.PdfWithUnknownPredictor())).Verdict);

    [Fact]
    public async Task ChainedFilters_AreNotInspected()
        => Assert.Equal(ScanVerdict.NotInspected,
            (await Make().ScanAsync("x.pdf", Samples.PdfWithFilterChain())).Verdict);

    [Fact]
    public async Task EmbeddedDepthExactlyAtMaximum_CanComplete()
    {
        var options = new FileScannerOptions { MaxEmbeddedDepth = 2 };
        Assert.Equal(ScanVerdict.Clean,
            (await Make(options).ScanAsync("x.pdf", Samples.PdfWithEmbeddedDepth(2))).Verdict);
    }

    [Fact]
    public async Task EmbeddedDepthAboveMaximum_IsNotInspected()
    {
        var options = new FileScannerOptions { MaxEmbeddedDepth = 2 };
        Assert.Equal(ScanVerdict.NotInspected,
            (await Make(options).ScanAsync("x.pdf", Samples.PdfWithEmbeddedDepth(3))).Verdict);
    }

    [Fact]
    public async Task AggregateDecompressionBudgetAcrossStreams_IsNotInspected()
    {
        var options = new FileScannerOptions
        {
            MaxDecompressedBytesPerStream = 1024,
            MaxTotalDecompressedBytes = 1500,
        };
        var pdf = Samples.PdfWithManySmallFlateStreams(count: 3, expandedBytesPerStream: 700);
        Assert.Equal(ScanVerdict.NotInspected, (await Make(options).ScanAsync("x.pdf", pdf)).Verdict);
    }

    [Fact]
    public async Task OoxmlBudgetExceeded_StopsBeforeLaterActiveContent()
    {
        var options = new FileScannerOptions
        {
            MaxDecompressedBytesPerStream = 1024,
            MaxTotalDecompressedBytes = 1500,
        };

        var result = await Make(options).ScanAsync(
            "x.docx", Samples.DocxWithOversizedEntryBeforeDde(2048));

        Assert.Equal(ScanVerdict.NotInspected, result.Verdict);
    }

    [Fact]
    public async Task AggregateEntryBudgetAcrossPdf_IsNotInspected()
    {
        var options = new FileScannerOptions { MaxContainerEntries = 6 };
        var pdf = Samples.PdfWithManySmallFlateStreams(count: 3, expandedBytesPerStream: 8);
        Assert.Equal(ScanVerdict.NotInspected, (await Make(options).ScanAsync("x.pdf", pdf)).Verdict);
    }

    [Fact]
    public async Task NestedAttachmentsShareOneDecompressionBudget()
    {
        var options = new FileScannerOptions
        {
            MaxDecompressedBytesPerStream = 700,
            MaxTotalDecompressedBytes = 700,
            MaxEmbeddedDepth = 2,
        };
        var pdf = Samples.PdfWithEmbeddedDepth(2);
        Assert.Equal(ScanVerdict.NotInspected, (await Make(options).ScanAsync("x.pdf", pdf)).Verdict);
    }

    [Fact]
    public async Task CancellationRequestedAtUploadEof_IsPropagatedBeforeStructuralInspection()
    {
        byte[] pdf = Samples.CleanPdf();
        using var cancellation = new CancellationTokenSource();
        using var stream = new CancelAtEofStream(pdf, cancellation);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            Make().ScanAsync("x.pdf", stream, stream.Length, cancellation.Token));
    }

    [Fact]
    public void CancellationInsidePdfBudget_IsNotConvertedToNotInspected()
    {
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        var budget = new ScanBudget(new FileScannerOptions(), cancellation.Token);

        Assert.ThrowsAny<OperationCanceledException>(() =>
            PdfStructuralInspector.Inspect(Samples.CleanPdf(), budget));
    }

    [Fact]
    public void CancellationInsideOoxmlBudget_IsNotSwallowedAsIncomplete()
    {
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        var budget = new ScanBudget(new FileScannerOptions(), cancellation.Token);

        Assert.ThrowsAny<OperationCanceledException>(() =>
            ActiveContentInspector.Inspect("x.docx", Samples.DocxWithDde(), budget));
    }

    [Fact]
    public void ScanBudget_LongMaxSentinel_DoesNotOverflowToEmptyRead()
    {
        var options = new FileScannerOptions
        {
            MaxDecompressedBytesPerStream = long.MaxValue,
            MaxTotalDecompressedBytes = long.MaxValue,
        };
        var budget = new ScanBudget(options);
        byte[] payload = [1, 2, 3, 4];

        Assert.Equal(payload, budget.ReadExpanded(new MemoryStream(payload), "sentinela"));
    }

    [Fact]
    public void FailedExpandedRead_IsChargedAgainstAggregateBudget()
    {
        var budget = new ScanBudget(new FileScannerOptions
        {
            MaxDecompressedBytesPerStream = 1024,
            MaxTotalDecompressedBytes = 1500,
        });

        Assert.Throws<ScanLimitExceededException>(() =>
            budget.ReadExpanded(new MemoryStream(new byte[2048]), "primeiro"));
        Assert.Equal(1025, budget.ExpandedBytes);
        Assert.Throws<ScanLimitExceededException>(() =>
            budget.ReadExpanded(new MemoryStream(new byte[600]), "segundo"));
    }

    [Fact]
    public void DivergentInjectedStructuralPolicy_IsRejectedAtConstruction()
    {
        var strict = new FileScannerOptions { AllowedExtensions = ["pdf"] };
        var permissiveValidator = new StructuralValidator(new FileScannerOptions());

        Assert.Throws<ArgumentException>(() => new FileScanService(strict, permissiveValidator));
    }

    [Fact]
    public void ZeroPerStreamLimit_IsRejectedBeforeProcessing()
        => Assert.Throws<ArgumentOutOfRangeException>(() =>
            Make(new() { MaxDecompressedBytesPerStream = 0 }));

    [Fact]
    public void NegativeTotalBudget_IsRejectedBeforeProcessing()
        => Assert.Throws<ArgumentOutOfRangeException>(() =>
            Make(new() { MaxTotalDecompressedBytes = -1 }));

    [Fact]
    public void PerStreamLimitAboveTotal_IsRejectedBeforeProcessing()
        => Assert.Throws<ArgumentException>(() => Make(new()
        {
            MaxDecompressedBytesPerStream = 2048,
            MaxTotalDecompressedBytes = 1024,
        }));

    [Fact]
    public void EntryLimitAboveSupportedCeiling_IsRejectedBeforeProcessing()
        => Assert.Throws<ArgumentOutOfRangeException>(() =>
            Make(new() { MaxContainerEntries = 100_001 }));

    [Fact]
    public void DepthAboveSupportedCeiling_IsRejectedBeforeProcessing()
        => Assert.Throws<ArgumentOutOfRangeException>(() =>
            Make(new() { MaxEmbeddedDepth = 17 }));

    [Fact]
    public async Task AntivirusMalicious_PrevailsAndKeepsAntivirusAttribution()
    {
        var result = await Make(virus: new StubVirus(ScanVerdict.Malicious))
            .ScanAsync("x.pdf", Samples.PdfWithLzwFilteredStreamHidingJs());
        Assert.Equal(ScanVerdict.Malicious, result.Verdict);
        Assert.Equal("stub-av", result.Engine);
    }

    [Fact]
    public async Task AntivirusError_PrevailsAndKeepsAntivirusAttribution()
    {
        var result = await Make(virus: new StubVirus(ScanVerdict.Error))
            .ScanAsync("x.pdf", Samples.PdfWithLzwFilteredStreamHidingJs());
        Assert.Equal(ScanVerdict.Error, result.Verdict);
        Assert.Equal("stub-av", result.Engine);
    }

    [Fact]
    public async Task CleanVerdict_HasNoWarningsOrIncompleteSideChannel()
    {
        var result = await Make().ScanAsync("x.pdf", Samples.CleanPdf());
        Assert.Equal(ScanVerdict.Clean, result.Verdict);
        Assert.True(result.Warnings is null or { Count: 0 });
        Assert.Null(result.Reason);
    }

    [Fact]
    public async Task AntivirusCleanReason_IsRemovedFromCleanVerdict()
    {
        var result = await Make(virus: new StubVirus(ScanVerdict.Clean))
            .ScanAsync("x.pdf", Samples.CleanPdf());

        Assert.Equal(ScanVerdict.Clean, result.Verdict);
        Assert.Equal("stub-av", result.Engine);
        Assert.Null(result.Reason);
    }

    private sealed class StubVirus(ScanVerdict verdict) : IVirusScanner
    {
        public string Name => "stub-av";

        public Task<(ScanVerdict Verdict, string? Reason)> ScanAsync(Stream content,
            CancellationToken ct) => Task.FromResult<(ScanVerdict, string?)>((verdict, "stub"));
    }

    private sealed class CancelAtEofStream(byte[] bytes, CancellationTokenSource cancellation) : Stream
    {
        private int position;
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => bytes.LongLength;
        public override long Position { get => position; set => throw new NotSupportedException(); }

        public override ValueTask<int> ReadAsync(Memory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            if (position >= bytes.Length)
            {
                cancellation.Cancel();
                return ValueTask.FromResult(0);
            }

            int count = Math.Min(buffer.Length, bytes.Length - position);
            bytes.AsMemory(position, count).CopyTo(buffer);
            position += count;
            return ValueTask.FromResult(count);
        }

        public override int Read(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException();
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException();
    }
}
