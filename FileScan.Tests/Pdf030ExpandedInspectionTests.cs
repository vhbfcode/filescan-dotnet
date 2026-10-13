using System.Text;
using FileScan.Scanning;
using Xunit;

namespace FileScan.Tests;

/// <summary>
/// 0.3.0 — ampliação do inspetor de PDF (T-333 do Fenix) mantendo o fail-closed. Cada ampliação tem
/// o teste do caso legítimo E o do caso malicioso/ambíguo equivalente, que continua recusado.
/// Fixtures 100% sintéticas (geradas em código); nenhum PDF real é versionado.
/// </summary>
public class Pdf030ExpandedInspectionTests
{
    private static FileScanService Make(FileScannerOptions? options = null) => new(options ?? new FileScannerOptions());

    private static async Task<ScanVerdict> Verdict(byte[] pdf, FileScannerOptions? options = null) =>
        (await Make(options).ScanAsync("x.pdf", pdf)).Verdict;

    // ---------------------------------------------------------------- filtros encadeados

    [Theory]
    [InlineData("[/ASCII85Decode/FlateDecode]")]
    [InlineData("[/ASCIIHexDecode/FlateDecode]")]
    [InlineData("[/ASCII85Decode]")]
    public async Task ChainedFilters_ValidChain_IsInspectedAndClean(string filters)
        => Assert.Equal(ScanVerdict.Clean, await Verdict(
            Samples.PdfWithChainedStream(filters, Encoding.ASCII.GetBytes("BT (texto benigno) Tj ET"))));

    [Fact]
    public async Task ChainedFilters_DecodedOutputIsStillScannedForJavaScript()
        => Assert.Equal(ScanVerdict.Rejected, await Verdict(Samples.PdfWithChainedStreamHidingJavaScript()));

    [Fact]
    public async Task ChainedFilters_EmbeddedExecutableInsideChain_IsRejected()
        => Assert.Equal(ScanVerdict.Rejected, await Verdict(Samples.PdfWithEmbeddedExeInChain()));

    [Fact]
    public async Task ChainedFilters_BeyondMaxChainLength_IsNotInspected()
        => Assert.Equal(ScanVerdict.NotInspected, await Verdict(Samples.PdfWithFiveFilterChain()));

    [Fact]
    public async Task ChainedFilters_WithUnsupportedCodecInChain_IsNotInspected()
        => Assert.Equal(ScanVerdict.NotInspected, await Verdict(Samples.PdfWithLzwInChain()));

    [Fact]
    public async Task ChainedFilters_InvalidAscii85_IsNotInspected()
        => Assert.Equal(ScanVerdict.NotInspected, await Verdict(Samples.PdfWithInvalidAscii85()));

    [Fact]
    public async Task ChainedFilters_FlateBombBehindAscii85_IsNotInspected()
    {
        var options = new FileScannerOptions { MaxDecompressedBytesPerStream = 1024 };
        byte[] pdf = Samples.PdfWithChainedStream("[/ASCII85Decode/FlateDecode]", new byte[256 * 1024]);
        var response = await Make(options).ScanAsync("x.pdf", pdf);
        Assert.Equal(ScanVerdict.NotInspected, response.Verdict);
    }

    [Fact]
    public async Task ChainedFilters_Ascii85ZShortcutBomb_IsRefusedBeforeDecoding()
    {
        // 4.000 'z' = 16.000 bytes potenciais; teto por stream de 1.024.
        var options = new FileScannerOptions { MaxDecompressedBytesPerStream = 1024 };
        var response = await Make(options).ScanAsync("x.pdf", Samples.PdfWithAscii85ZBomb(4000));
        Assert.Equal(ScanVerdict.NotInspected, response.Verdict);
        Assert.Contains("expansão potencial", response.Reason);
    }

    [Fact]
    public async Task ChainedFilters_AsciiFilterOutputIsChargedToTheAggregateBudget()
    {
        // 5 streams de 400 bytes decodificados (A85 ~500 chars): cada um cabe no teto por stream
        // (1.000), a soma (2.000) não cabe no agregado de 1.500.
        var options = new FileScannerOptions
        {
            MaxDecompressedBytesPerStream = 1000,
            MaxTotalDecompressedBytes = 1500,
        };
        byte[] pdf = Samples.PdfWithManyAscii85Streams(count: 5, decodedBytesPerStream: 400);
        Assert.Equal(ScanVerdict.NotInspected, await Verdict(pdf, options));
        Assert.Equal(ScanVerdict.Clean, await Verdict(pdf, new()));
    }

    [Fact]
    public async Task ChainedFilters_Ascii85ZWithinBudget_IsClean()
        => Assert.Equal(ScanVerdict.Clean, await Verdict(Samples.PdfWithAscii85ZBomb(100)));

    [Theory]
    [InlineData("[null null]", ScanVerdict.Clean)]
    [InlineData("[null<</Columns 1>>]", ScanVerdict.Clean)]
    [InlineData("[null<</Predictor 12/Columns 1>>]", ScanVerdict.NotInspected)]
    [InlineData("[<</Predictor 2>>null]", ScanVerdict.NotInspected)]
    [InlineData("<</Predictor 15>>", ScanVerdict.NotInspected)]
    public async Task ChainedFilters_DecodeParmsPredictorStillFailsClosed(string decodeParms, ScanVerdict expected)
        => Assert.Equal(expected, await Verdict(Samples.PdfWithChainedStreamAndParms(decodeParms)));

    // ---------------------------------------------------------------- predictor PNG

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    public async Task PngPredictor_EveryRowFilterDecodesExactly_SoTheNameInsideIsFound(int filterType)
        => Assert.Equal(ScanVerdict.Rejected,
            await Verdict(Samples.PdfWithPredictedStreamHidingJavaScript(filterType)));

    [Fact]
    public async Task PngPredictor_XrefStreamWithPredictor12_IsInspected()
    {
        Assert.Equal(ScanVerdict.Clean, await Verdict(Samples.PdfWithXrefStream(predictor12: false)));
        Assert.Equal(ScanVerdict.Clean, await Verdict(Samples.PdfWithXrefStream(predictor12: true)));
    }

    [Fact]
    public async Task PngPredictor_TiffPredictor_StillNotInspected()
        => Assert.Equal(ScanVerdict.NotInspected, await Verdict(
            Samples.PdfWithXrefStream(true, "/DecodeParms<</Columns 5/Predictor 2>>")));

    [Fact]
    public async Task PngPredictor_InvalidRowFilterByte_IsNotInspected()
        => Assert.Equal(ScanVerdict.NotInspected, await Verdict(Samples.PdfWithXrefStream(true, null, data =>
        {
            for (int row = 0; row < data.Length; row += 6) data[row] = 9;
            return data;
        })));

    [Fact]
    public async Task PngPredictor_DataNotMultipleOfRowStride_IsNotInspected()
        => Assert.Equal(ScanVerdict.NotInspected, await Verdict(
            Samples.PdfWithXrefStream(true, null, data => [.. data, (byte)0])));

    [Theory]
    [InlineData("/DecodeParms<</Columns 4/Predictor 12>>")]
    [InlineData("/DecodeParms<</Columns 5/Predictor /Foo>>")]
    [InlineData("/DecodeParms<</Columns 5/Predictor 12.5>>")]
    [InlineData("/DecodeParms<</Columns 0/Predictor 12>>")]
    [InlineData("/DecodeParms<</Columns 5/Predictor 12/BitsPerComponent 3>>")]
    [InlineData("/DecodeParms 9 0 R")]
    public async Task PngPredictor_MalformedOrMismatchedParameters_AreNotInspected(string decodeParms)
        => Assert.Equal(ScanVerdict.NotInspected, await Verdict(Samples.PdfWithXrefStream(true, decodeParms)));

    [Fact]
    public async Task PngPredictor_BenignContentStream_IsCleanButInvalidRowFilterOrIndirectParmsAreNot()
    {
        Assert.Equal(ScanVerdict.Clean, await Verdict(Samples.PdfWithPredictedBenignStream()));

        // Tipo de filtro de linha fora de 0..4: se virasse "none" o stream seria lido como Clean.
        Assert.Equal(ScanVerdict.NotInspected, await Verdict(Samples.PdfWithPredictedBenignStream(
            tamper: data => { data[0] = 9; return data; })));

        // /DecodeParms indireto: não se sabe se há predictor => fail-closed (e não "sem predictor").
        Assert.Equal(ScanVerdict.NotInspected, await Verdict(Samples.PdfWithPredictedBenignStream(
            "/DecodeParms 9 0 R", withParmsObject: true, rowFilter: 0)));
    }

    [Fact]
    public async Task PngPredictor_OnAnAsciiFilter_IsNotInspected()
        => Assert.Equal(ScanVerdict.NotInspected, await Verdict(Samples.PdfWithAsciiFilterPredictor()));

    [Fact]
    public async Task PngPredictor_Output_NeverExceedsTheInflatedBudget()
    {
        // A inflação (orçamento) acontece antes do predictor: a bomba continua sendo barrada na inflação.
        var options = new FileScannerOptions { MaxDecompressedBytesPerStream = 1024 };
        Assert.Equal(ScanVerdict.NotInspected,
            await Verdict(Samples.PdfWithPredictedStreamHidingJavaScript(2, columns: 4000), options));
    }

    // ---------------------------------------------------------------- final do arquivo (%%EOF)
    // Regra (VOLTA r1): depois do ÚLTIMO startxref só "<offset> EOL %%EOF" e whitespace.
    // Nenhuma cauda é tolerada e nenhuma varredura textual de cauda pode terminar em Clean.

    public static IEnumerable<object[]> HostileTails() =>
    [
        ["\n<script>alert('x')</script>"],
        ["\n<svg onload =alert(1)>"],
        ["\n<img src=x onerror\t=alert(1)>"],
        ["\n<a href=\"java&#115;cript:alert(1)\">x</a>"],
        ["\n<iframe src=\"data:text/html,<b>x</b>\"></iframe>"],
        ["\n<body onpageshow=alert(1)>"],
        ["\n<meta http-equiv=refresh content=\"0;url=//evil\">"],
        ["\nnao-e-whitespace"],
        ["\nOcorreu um erro inesperado ao consultar o documento."],
        ["\nstartxref\n9\n"],
        ["\n4 0 obj<</Type/Page"],
        ["\nendstream"],
        ["\u0001"],
        ["\u0000<script>alert(1)</script>"],
    ];

    [Theory]
    [MemberData(nameof(HostileTails))]
    public async Task TrailingBytes_AreNeverTolerated_AndNeverClean(string tail)
        => Assert.Equal(ScanVerdict.NotInspected,
            await Verdict(Samples.PdfWithTail(Encoding.Latin1.GetBytes(tail))));

    [Fact]
    public async Task TrailingBytes_Utf16Script_IsNotInspected()
    {
        byte[] utf16 = [.. new byte[] { 0x0A }, .. Encoding.Unicode.GetBytes("<script>alert(1)</script>")];
        Assert.Equal(ScanVerdict.NotInspected, await Verdict(Samples.PdfWithTail(utf16)));
        Assert.Equal(ScanVerdict.NotInspected, await Verdict(Samples.PdfWithTail([0x0A, 0xFF, 0xFE, 0x41])));
        Assert.Equal(ScanVerdict.NotInspected,
            await Verdict(Samples.PdfWithTail([0x0A, 0x50, 0x4B, 0x03, 0x04, 0x14, 0x00])));
    }

    [Fact]
    public async Task TrailingActionNames_AreFoundButNeverClean()
        => Assert.Equal(ScanVerdict.Rejected,
            await Verdict(Samples.PdfWithTail(Encoding.ASCII.GetBytes("\n/JavaScript /Launch"))));

    [Theory]
    [InlineData("\n<script>alert(1)</script>\n%%EOF")]
    [InlineData("\n/JavaScript /Launch\n%%EOF")]
    [InlineData("\n1 0 obj<</Type/Catalog/Pages 2 0 R/OpenAction<</S/JavaScript/JS(x)>>>>endobj\n%%EOF")]
    [InlineData("\n1 0 obj<</Type/Catalog/Pages 2 0 R/OpenAction 9 0 R>>endobj\n%%EOF")]
    [InlineData("\n%%EOF\n%%EOF")]
    public async Task SecondEof_DoesNotCancelTheTailCheck(string appended)
    {
        // Era Clean na 0.2.0: o 2º %%EOF fazia a checagem olhar só os últimos bytes.
        var verdict = await Verdict(Samples.PdfWithTail(Encoding.ASCII.GetBytes(appended)));
        Assert.NotEqual(ScanVerdict.Clean, verdict);
    }

    [Fact]
    public async Task SecondEof_AfterHtml_IsNotInspected()
        => Assert.Equal(ScanVerdict.NotInspected, await Verdict(
            Samples.PdfWithTail(Encoding.ASCII.GetBytes("\n<script>alert(1)</script>\n%%EOF"))));

    [Fact]
    public async Task IncrementalUpdate_Legitimate_IsClean_AndMaliciousIsNotClean()
    {
        // Atualização incremental legítima: tem o seu próprio xref/startxref/%%EOF.
        Assert.Equal(ScanVerdict.Clean, await Verdict(Samples.PdfWithIncrementalUpdate("<</Tipo/Teste>>")));

        // Atualização maliciosa BEM formada: o PdfPig segue o /Prev e o objeto novo é percorrido.
        Assert.Equal(ScanVerdict.Rejected, await Verdict(
            Samples.PdfWithIncrementalUpdate("<</S/JavaScript/JS(app.alert\\('x'\\))>>")));

        // Atualização maliciosa SEM xref próprio (objeto solto + %%EOF) nunca é Clean.
        Assert.NotEqual(ScanVerdict.Clean, await Verdict(Samples.PdfWithTail(Encoding.ASCII.GetBytes(
            "\n4 0 obj<</S/JavaScript/JS(x)>>endobj\n%%EOF\n"))));

        // Cauda depois do %%EOF da atualização incremental continua recusada.
        Assert.Equal(ScanVerdict.NotInspected, await Verdict(
            Samples.PdfWithIncrementalUpdate("<</Tipo/Teste>>", Encoding.ASCII.GetBytes("<script>x</script>"))));
    }

    [Fact]
    public async Task Eof_ExactShapeIsRequired_AfterTheLastStartxref()
    {
        // Forma canônica: Clean.
        Assert.Equal(ScanVerdict.Clean, await Verdict(Samples.PdfWithEofShape(n => $"startxref\n{n}\n%%EOF\n")));
        Assert.Equal(ScanVerdict.Clean, await Verdict(Samples.PdfWithEofShape(n => $"startxref\r\n{n}\r\n%%EOF")));

        // Variações que um leitor tolerante engoliria: aqui, nenhuma é Clean.
        Assert.Equal(ScanVerdict.NotInspected, await Verdict(Samples.PdfWithEofShape(n => $"startxref\n{n}%%EOF\n")));
        Assert.Equal(ScanVerdict.NotInspected, await Verdict(Samples.PdfWithEofShape(n => $"startxref{n}\n%%EOF\n")));
        Assert.Equal(ScanVerdict.NotInspected, await Verdict(Samples.PdfWithEofShape(n => $"startxref\n{n}abc\n%%EOF\n")));
        Assert.Equal(ScanVerdict.NotInspected, await Verdict(Samples.PdfWithEofShape(n => $"startxref\n{n}\nXXXXX\n")));
        Assert.Equal(ScanVerdict.NotInspected, await Verdict(Samples.PdfWithEofShape(n => $"startxref\n{n}\n")));
    }

    [Fact]
    public async Task Eof_WhitespaceAndOffsetShapes()
    {
        // Variações aceitas de EOL/whitespace antes e depois do %%EOF continuam Clean.
        Assert.Equal(ScanVerdict.Clean, await Verdict(Samples.PdfWithTail(Encoding.ASCII.GetBytes("\r\n \n\t"))));
        Assert.Equal(ScanVerdict.NotInspected, await Verdict(Samples.PdfWithNoStartxrefOffset()));
        Assert.Equal(ScanVerdict.NotInspected, await Verdict(Samples.PdfTruncatedAfterIntermediateEof()));
        Assert.Equal(ScanVerdict.NotInspected, await Verdict(Samples.PdfWithShortTruncatedIncrementalUpdate()));
    }

    // ---------------------------------------------------------------- /EF fora de /Type /Filespec

    [Fact]
    public async Task EfInAnyDictionary_IsAFileSpec_SoTheAttachmentIsInspected()
    {
        // /GoToE (sem /Type /Filespec) apontando para um EXE: antes escapava como "não-anexo".
        Assert.Equal(ScanVerdict.Rejected, await Verdict(Samples.PdfWithEfOutsideFilespec(dct: false)));

        // O mesmo anexo travestido de imagem DCT não pode ser pulado: falha fechado.
        Assert.Equal(ScanVerdict.NotInspected, await Verdict(Samples.PdfWithEfOutsideFilespec(dct: true)));

        // /EF malformado, em qualquer dicionário, também falha fechado.
        Assert.Equal(ScanVerdict.NotInspected, await Verdict(Samples.PdfWithMalformedEf()));
    }

    // ---------------------------------------------------------------- cobertura de bytes (VOLTA r2)

    public static IEnumerable<object[]> TextGarbage() =>
    [
        ["<script>alert(1)</script>"],
        ["<svg onload=alert(1)>"],
        ["texto solto qualquer"],
    ];

    [Theory]
    [MemberData(nameof(TextGarbage))]
    public async Task Coverage_GarbageBeforeAFakeStartxref_IsNotInspected(string garbage)
    {
        byte[] bytes = Encoding.ASCII.GetBytes("\n" + garbage);
        Assert.Equal(ScanVerdict.NotInspected, await Verdict(Samples.PdfWithGarbageAndFakeStartxref(bytes)));
        Assert.Equal(ScanVerdict.NotInspected, await Verdict(Samples.PdfWithGarbageAndEmptyXrefSection(bytes)));
        Assert.Equal(ScanVerdict.NotInspected, await Verdict(Samples.PdfLinearizedSynthetic("\n" + garbage + "\n")));
    }

    [Fact]
    public async Task Coverage_ExecutableOrActionNamesAsGarbage_NeverClean()
    {
        Assert.Equal(ScanVerdict.NotInspected, await Verdict(Samples.PdfWithGarbageAndFakeStartxref(Samples.MzGarbage())));
        Assert.Equal(ScanVerdict.NotInspected, await Verdict(Samples.PdfWithGarbageAndEmptyXrefSection(Samples.MzGarbage())));

        byte[] names = Encoding.ASCII.GetBytes("\n/JavaScript /Launch");
        Assert.Equal(ScanVerdict.Rejected, await Verdict(Samples.PdfWithGarbageAndFakeStartxref(names)));
        Assert.Equal(ScanVerdict.Rejected, await Verdict(Samples.PdfWithGarbageAndEmptyXrefSection(names)));
    }

    [Fact]
    public async Task Coverage_LegitimateLayouts_StayClean()
    {
        Assert.Equal(ScanVerdict.Clean, await Verdict(Samples.PdfWithIncrementalUpdate("<</Tipo/Teste>>")));
        Assert.Equal(ScanVerdict.Clean, await Verdict(Samples.PdfLinearizedSynthetic()));
        Assert.Equal(ScanVerdict.Clean, await Verdict(Samples.PdfWithFreeEntries()));
        Assert.Equal(ScanVerdict.Clean, await Verdict(Samples.PdfWithOffsetsPointingAtLeadingWhitespace()));
        Assert.Equal(ScanVerdict.Clean, await Verdict(Samples.PdfWithXrefStream(predictor12: true)));
        Assert.Equal(ScanVerdict.Clean, await Verdict(Samples.PdfWithXrefStream(predictor12: false)));
    }

    [Fact]
    public async Task Coverage_RealObjectStreamDocuments_StayCoveredAndStillInspected()
    {
        // ObjStm + xref stream tipo 2: o conteúdo comprimido continua sendo percorrido (JS achado)...
        Assert.Equal(ScanVerdict.Rejected, await Verdict(Samples.PdfWithJavaScriptInRealObjectStream()));
    }

    [Fact]
    public async Task Coverage_BytesBetweenObjects_WhitespaceAndCommentsOkTextNot()
    {
        Assert.Equal(ScanVerdict.Clean, await Verdict(Samples.PdfWithBetweenObjects("\n \r\n\t\n")));
        Assert.Equal(ScanVerdict.Clean, await Verdict(Samples.PdfWithBetweenObjects("% um comentario <script>\n")));
        Assert.Equal(ScanVerdict.Clean, await Verdict(Samples.PdfLinearizedSynthetic("\n% comentario\n  \n")));

        Assert.Equal(ScanVerdict.NotInspected, await Verdict(Samples.PdfWithBetweenObjects("texto solto\n")));
        Assert.Equal(ScanVerdict.NotInspected, await Verdict(Samples.PdfWithBetweenObjects("<script>x</script>\n")));
        Assert.Equal(ScanVerdict.NotInspected, await Verdict(Samples.PdfWithBetweenObjects("endobj\n")));
        Assert.Equal(ScanVerdict.NotInspected, await Verdict(Samples.PdfWithBetweenObjects("123\n")));
    }

    [Fact]
    public async Task Coverage_OrphanObjects_AreScannedOrRefused()
    {
        // Objeto bem formado, fora de qualquer xref: nomes de ação são achados.
        Assert.Equal(ScanVerdict.Rejected, await Verdict(
            Samples.PdfWithOrphanObject("<</S/JavaScript/JS(app.alert\\('x'\\))>>")));
        // Órfão benigno e sem stream: aceito (nenhum achado).
        Assert.Equal(ScanVerdict.Clean, await Verdict(Samples.PdfWithOrphanObject("<</Tipo/Inofensivo>>")));
        // Órfão com stream não é inspecionável: fail-closed.
        Assert.Equal(ScanVerdict.NotInspected, await Verdict(
            Samples.PdfWithOrphanObject("/Filter/FlateDecode", new byte[] { 1, 2, 3 })));
    }

    [Fact]
    public async Task Coverage_ScanCostStaysLinear_ForManyObjects()
    {
        var watch = System.Diagnostics.Stopwatch.StartNew();
        byte[] pdf = Samples.PdfWithManyObjects(40_000);
        Assert.Equal(ScanVerdict.Clean, await Verdict(pdf));
        watch.Stop();
        // Folga enorme de propósito (CI lento); o ponto é não ser quadrático.
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(20), $"varredura lenta: {watch.Elapsed}");
    }

    // ---------------------------------------------------------------- guarda pré-Open (VOLTA r4)
    // O PdfDocument.Open do PdfPig 0.1.16 recursa sem limite nestas estruturas; estouro de pilha derruba o
    // PROCESSO. Sem a guarda, estes testes abortam a run inteira (o `dotnet test` sai com código != 0).

    [Fact]
    public async Task PreOpen_DestsKidsCycle_OfTwoNodes_IsNotInspected()
        => Assert.Equal(ScanVerdict.NotInspected, await Verdict(Samples.PdfWithDests(2, cycle: true)));

    [Theory]
    [InlineData(5_000)]
    [InlineData(20_000)]
    public async Task PreOpen_DestsKidsChain_IsNotInspected(int nodes)
        => Assert.Equal(ScanVerdict.NotInspected, await Verdict(Samples.PdfWithDests(nodes)));

    [Fact]
    public async Task PreOpen_DestsKids_ExponentialShapes_AreNotInspected()
    {
        Assert.Equal(ScanVerdict.NotInspected, await Verdict(Samples.PdfWithDestsRepeatedKid(40)));
        Assert.Equal(ScanVerdict.NotInspected, await Verdict(Samples.PdfWithDestsDiamond(40)));
    }

    [Theory]
    [InlineData(5_000)]
    [InlineData(20_000)]
    public async Task PreOpen_DeepPageTree_IsNotInspected(int depth)
        => Assert.Equal(ScanVerdict.NotInspected, await Verdict(Samples.PdfWithDeepPageTree(depth)));

    [Theory]
    [InlineData(2, true, false)]
    [InlineData(40, false, false)]
    [InlineData(5_000, false, false)]
    [InlineData(20_000, false, false)]
    [InlineData(2, true, true)]
    [InlineData(20_000, false, true)]
    public async Task PreOpen_IndirectReferenceAliasCycleOrChain_IsNotInspected(int length, bool cycle, bool arrayWrapped)
        => Assert.Equal(ScanVerdict.NotInspected, await Verdict(Samples.PdfWithAliasChain(length, cycle, arrayWrapped)));

    [Fact]
    public async Task PreOpen_InfoAliasCycles_AreNotInspected()
    {
        Assert.Equal(ScanVerdict.NotInspected, await Verdict(Samples.PdfWithInfoAliasCycle()));
        Assert.Equal(ScanVerdict.NotInspected, await Verdict(Samples.PdfWithInfoValueSelfAlias()));
        Assert.Equal(ScanVerdict.NotInspected, await Verdict(Samples.PdfWithInfoValueAliasChain(50_000)));
    }

    [Fact]
    public async Task PreOpen_SameAttacks_WithTheCatalogInsideAnObjectStream_AreNotInspected()
    {
        Assert.Equal(ScanVerdict.NotInspected, await Verdict(Samples.PdfWithObjectStream(
            Samples.ObjectStreamDocument("/Names<</Dests 10 0 R>>", Samples.DestsChain(2, cycle: true)))));
        Assert.Equal(ScanVerdict.NotInspected, await Verdict(Samples.PdfWithObjectStream(
            Samples.ObjectStreamDocument("/Names<</Dests 10 0 R>>", Samples.DestsChain(5_000)))));
        Assert.Equal(ScanVerdict.NotInspected, await Verdict(Samples.PdfWithObjectStream(
            Samples.ObjectStreamDocument("/Names<</Dests 10 0 R>>", Samples.DestsChain(20_000)))));
    }

    [Fact]
    public async Task PreOpen_LegitimateStructures_StayClean()
    {
        // name tree /Dests real (3 níveis), /Dests antigo (dicionário plano), apelido de um salto
        Assert.Equal(ScanVerdict.Clean, await Verdict(Samples.PdfWithDests(3)));
        Assert.Equal(ScanVerdict.Clean, await Verdict(Samples.PdfWithDests(40)));
        Assert.Equal(ScanVerdict.Clean, await Verdict(Samples.PdfWithDeepPageTree(5)));
        Assert.Equal(ScanVerdict.Clean, await Verdict(Samples.PdfWithOldStyleDests()));

        // catálogo, árvore e name tree dentro de object stream (PDF moderno com xref stream)
        Assert.Equal(ScanVerdict.Clean, await Verdict(Samples.PdfWithObjectStream(
            Samples.ObjectStreamDocument("/Names<</Dests 10 0 R>>", Samples.DestsChain(3)))));
        Assert.Equal(ScanVerdict.Clean, await Verdict(Samples.PdfWithObjectStream(
            Samples.ObjectStreamDocument("", []))));
    }

    // ---------------------------------------------------------------- contornos da guarda (VOLTA r5)
    // Princípio: a guarda lê com os tokenizadores do PdfPig e RECUSA o que não entende. X1..X5 = contornos
    // achados pela 2ª linha (cada um derrubava o processo por estouro de pilha a partir do mesmo ciclo de 2 nós).

    [Fact]
    public async Task X0_Control_DestsCycle() => Assert.Equal(ScanVerdict.NotInspected,
        await Verdict(Samples.PdfWithDestsRaw("<</Kids[11 0 R]>>", "<</Kids[10 0 R]>>")));

    [Fact]
    public async Task X1_EscapedKey_K_hash69_ds_IsNotInspected() => Assert.Equal(ScanVerdict.NotInspected,
        await Verdict(Samples.PdfWithDestsRaw("<</K#69ds[11 0 R]>>", "<</K#69ds[10 0 R]>>")));

    [Fact]
    public async Task X2_CommentsInsideReferences_AreNotInspected()
    {
        Assert.Equal(ScanVerdict.NotInspected, await Verdict(
            Samples.PdfWithDestsRaw("<</Kids[11 %c\n0 R]>>", "<</Kids[10 %c\n0 R]>>")));
        Assert.Equal(ScanVerdict.NotInspected, await Verdict(
            Samples.PdfWithDestsRaw("<</Kids %c\n[11 0 R]>>", "<</Kids %c\n[10 0 R]>>")));
    }

    [Theory]
    [InlineData("/Type/ObjStm")]                 // controle
    [InlineData("")]                             // X3: ObjStm SEM /Type
    [InlineData("/Type/Obj#53tm")]               // X4: /Type escapado
    [InlineData("/Type/Foo")]                    // /Type qualquer
    [InlineData("/T#79pe/Obj#53tm")]             // chave E valor escapados
    public async Task X3_X4_ObjectStreamTypeVariants_AreNotInspected(string typePart)
        => Assert.Equal(ScanVerdict.NotInspected, await Verdict(Samples.PdfWithObjectStream(
            Samples.ObjectStreamDocument("/Names<</Dests 10 0 R>>", Samples.DestsChain(2, cycle: true)), typePart)));

    [Fact]
    public async Task X3_ObjectStreamWithExtends_IsNotInspected() => Assert.Equal(ScanVerdict.NotInspected,
        await Verdict(Samples.PdfWithObjectStream(
            Samples.ObjectStreamDocument("/Names<</Dests 10 0 R>>", Samples.DestsChain(2, cycle: true)),
            "", "/Extends 99 0 R")));

    [Fact]
    public async Task X5_ResolveNeverTruncatesSilently_ManyAliasDefinitions_AreNotInspected()
        => Assert.Equal(ScanVerdict.NotInspected, await Verdict(Samples.PdfWithManyAliasDefinitions(10_001)));

    [Fact]
    public async Task HiddenObjectsInsideStreamData_ReachedByXrefOffsets_AreNotInspected()
        => Assert.Equal(ScanVerdict.NotInspected, await Verdict(Samples.PdfWithHiddenObjectsInsideStream()));

    // ---------------------------------------------------------------- VOLTA r6

    [Theory]
    [InlineData(1)]   // Y1
    [InlineData(2)]   // Y2
    [InlineData(5)]
    public async Task Y1_Y2_DirectDictionariesInsideKids_JoinTheGraph(int directLevels)
        => Assert.Equal(ScanVerdict.NotInspected, await Verdict(Samples.PdfWithDestsDirectKids(directLevels)));

    [Fact]
    public async Task Y3_KidsHeldByAnArrayWithADirectDictionary_JoinsTheGraph()
        => Assert.Equal(ScanVerdict.NotInspected,
            await Verdict(Samples.PdfWithDestsKidsHeldByAnArrayWithDirectDictionary()));

    [Fact]
    public async Task DirectKids_WithoutACycle_StayClean()
    {
        // dicionário direto dentro de /Kids que NÃO fecha ciclo: legítimo.
        Assert.Equal(ScanVerdict.Clean, await Verdict(Samples.PdfWithDestsRaw(
            "<</Kids[<</Names[(a)[3 0 R/Fit]]>>]>>", "<</Names[(b)[3 0 R/Fit]]>>")));
    }

    [Theory]
    [InlineData("")]              // B1
    [InlineData("19")]            // B3: entradas de 19 bytes
    [InlineData("headerspace")]   // B5: espaço extra no cabeçalho da seção
    public async Task B1_B3_B5_ObjectsWrittenInsideStreamData_OutsideTheXref_AreNotInspected(string xrefStyle)
        => Assert.Equal(ScanVerdict.NotInspected, await Verdict(Samples.PdfWithCycleOnlyInsideStreamData(xrefStyle)));

    [Theory]
    [InlineData("string", "dangling")]    // T1: cópia oculta em string + referência pendente
    [InlineData("comment", "dangling")]   // T2: em comentário
    [InlineData("dct", "dangling")]       // T3: em dados DCT
    [InlineData("string", "generation")]  // T5: gatilho = geração != 0 numa referência
    [InlineData("comment", "mismatch")]   // T6: gatilho = entrada de xref que leva a OUTRO objeto
    [InlineData("dct", "mismatch")]
    public async Task T_HiddenCopyOfAnInUseNode_WithABruteForceTriggerReachable_IsNotInspected(string where, string trigger)
        => Assert.Equal(ScanVerdict.NotInspected, await Verdict(Samples.PdfWithHiddenCopyOfInUseNode(where, trigger)));

    [Theory]
    [InlineData("string")]
    [InlineData("comment")]
    [InlineData("dct")]
    public async Task T4_HiddenCopyOfAnInUseNode_WithoutAnyTrigger_IsClean(string where)
        => Assert.Equal(ScanVerdict.Clean, await Verdict(Samples.PdfWithHiddenCopyOfInUseNode(where, "none")));

    [Theory]
    [InlineData("dangling")]
    [InlineData("generation")]
    [InlineData("mismatch")]
    public async Task T_Trigger_WithoutAnyHiddenCopy_IsClean(string trigger)
        => Assert.Equal(ScanVerdict.Clean, await Verdict(Samples.PdfWithHiddenCopyOfInUseNode("none", trigger)));

    [Theory]
    [InlineData("dangling")]       // T7: força bruta alcançável por referência pendente
    [InlineData("containerFree")]  // T8: o container do ObjStm é entrada livre: só a cópia oculta o define
    public async Task T7_T8_HiddenCopyOfTheObjectStream_WithATriggerReachable_IsNotInspected(string trigger)
        => Assert.Equal(ScanVerdict.NotInspected, await Verdict(Samples.PdfWithHiddenCopyOfTheObjectStream(trigger)));

    [Fact]
    public async Task T7_HiddenCopyOfTheObjectStream_WithoutAnyTrigger_IsClean()
        => Assert.Equal(ScanVerdict.Clean, await Verdict(Samples.PdfWithHiddenCopyOfTheObjectStream("none")));

    [Fact]
    public async Task T9_SelfReferencingPrev_MakesBruteForceReachable_SoAHiddenCopyIsRefused_ButTheFileAloneIsClean()
    {
        Assert.Equal(ScanVerdict.NotInspected, await Verdict(Samples.PdfWithSelfReferencingPrev(hiddenCopy: true)));
        Assert.Equal(ScanVerdict.Clean, await Verdict(Samples.PdfWithSelfReferencingPrev(hiddenCopy: false)));
    }

    [Fact]
    public async Task T9b_SelfReferencingPrev_WithJunkBetweenTheTwoNumbers_IsNotInspected_OnlyTheXrefBruteForcerDetectorSeesIt()
        => Assert.Equal(ScanVerdict.NotInspected, await Verdict(Samples.PdfWithSelfReferencingPrev(hiddenCopy: true, interleaved: true)));

    [Fact]
    public async Task O1_O0_OrphanXrefSection_IsNotTheXrefPdfPigUses_SoItsInUseEntriesDoNotCount()
    {
        // O1: 10/11 só na seção órfã (livres na principal) + cópia oculta do nó 11 ⇒ a força bruta do PdfPig os acha.
        Assert.Equal(ScanVerdict.NotInspected, await Verdict(Samples.PdfWithOrphanXrefSection(hiddenCopy: true)));
        // O0: a mesma estrutura sem a cópia oculta não tem nada a esconder.
        Assert.Equal(ScanVerdict.Clean, await Verdict(Samples.PdfWithOrphanXrefSection(hiddenCopy: false)));
    }

    [Fact]
    public async Task O2_OrphanXrefSectionAlone_IsAReachableBruteForceTrigger_EvenWithTheNodesInUseInTheMainSection()
    {
        Assert.Equal(ScanVerdict.NotInspected, await Verdict(Samples.PdfWithOrphanXrefSection(hiddenCopy: true, freeInMain: false)));
        Assert.Equal(ScanVerdict.Clean, await Verdict(Samples.PdfWithOrphanXrefSection(hiddenCopy: false, freeInMain: false)));
    }

    [Fact]
    public void D1_D0_GuardAlone_RefusesAHiddenObjectStreamContainerWhoseEntryIsFree()
    {
        // Em nível da guarda (as camadas seguintes também recusam o container órfão, o que mascarava o gatilho "d").
        Assert.Contains("força bruta", GuardRefusal(Samples.PdfWithHiddenCopyOfTheObjectStream("containerFree")));
        Assert.Null(GuardRefusal(Samples.PdfWithHiddenCopyOfTheObjectStream("containerFreeNoCopy")));
    }

    private static string? GuardRefusal(byte[] content)
    {
        var budget = new ScanBudget(new FileScannerOptions());
        return PdfPreOpenGuard.Check(content, PdfByteCoverage.Scan(content, budget), budget).Refusal;
    }

    [Fact]
    public async Task LB_DanglingOrFreeReference_WithoutAnyHiddenObject_IsClean()
    {
        // VOLTA r7: referência pendente/livre SEM "N g obj" escondido não recusa (o PdfPig resolve para null).
        Assert.Equal(ScanVerdict.Clean, await Verdict(Samples.PdfWithDanglingReferenceWithoutHiddenObject()));
        Assert.Equal(ScanVerdict.Clean, await Verdict(Samples.PdfWithDestsRaw(
            "<</Names[(a)[99 0 R/Fit]]>>", "<</Names[(b)[3 0 R/Fit]]>>")));
        Assert.Equal(ScanVerdict.Clean, await Verdict(Samples.PdfWithInfoPointingAtAnUnlistedObject()));
        Assert.Equal(ScanVerdict.Clean, await Verdict(Samples.PdfWithFreeEntryReferenced()));
    }

    [Fact]
    public async Task ObjectDefinedInTheFileButMarkedFree_IsNotHidden_AndStaysClean()
        => Assert.Equal(ScanVerdict.Clean, await Verdict(Samples.PdfWithObjectDefinedInFileButMarkedFree()));

    [Theory]
    [InlineData("dct")]       // F1: dados DCT de uma imagem
    [InlineData("comment")]   // F2: comentário %
    [InlineData("string")]    // F3: string literal
    public async Task F1_F2_F3_CycleHiddenInDctCommentOrString_WithObjectsMarkedFree_IsNotInspected(string where)
        => Assert.Equal(ScanVerdict.NotInspected, await Verdict(Samples.PdfWithCycleHiddenAndMarkedFree(where)));

    [Fact]
    public async Task LC_LD_ObjectMarkerText_ThatNobodyReferences_IsClean()
    {
        // LC: content stream com o TEXTO "7 0 obj" que ninguém referencia; LD: PDF anexado sem compressão.
        Assert.Equal(ScanVerdict.Clean, await Verdict(Samples.PdfWithUnfilteredStreamData("texto\n7 0 obj\n<<>>\nendobj\n")));
        Assert.Equal(ScanVerdict.Clean, await Verdict(Samples.PdfWithUncompressedEmbeddedPdf()));
        Assert.Equal(ScanVerdict.Clean, await Verdict(Samples.PdfWithUnfilteredStreamData("BT (um object qualquer, sem marcador) Tj ET")));
        Assert.Equal(ScanVerdict.Clean, await Verdict(Samples.PdfWithUnfilteredStreamData("obj 1 2 obj3 x1 2 object")));
    }

    [Fact]
    public async Task XrefLinks_PointingAtObjectsInsteadOfSections_AreNotInspected()
    {
        // O PdfPig cairia em força bruta (lendo o arquivo todo, inclusive objetos escondidos): recusa.
        Assert.Equal(ScanVerdict.NotInspected, await Verdict(Samples.PdfWithStartxrefPointingAtAnObject()));
        Assert.Equal(ScanVerdict.NotInspected, await Verdict(Samples.PdfWithUpdatePrevPointingAtAnObject()));
        Assert.Equal(ScanVerdict.Clean, await Verdict(Samples.PdfWithIncrementalUpdate("<</Tipo/Teste>>")));
    }

    [Fact]
    public async Task L1_LegitimatePageTreeRestructuringUpdate_KnownLimitation_IsNotInspected()
    {
        // LIMITAÇÃO CONHECIDA (README/CHANGELOG): a guarda une TODAS as definições de um objeto (não sabe qual o
        // PdfPig usará) e a página 3 aparece com dois pais (o antigo e o novo) => "nó compartilhado" => recusa.
        // É o lado seguro. Fica registrado em teste para a mudança não passar despercebida.
        Assert.Equal(ScanVerdict.NotInspected, await Verdict(Samples.PdfWithPageTreeRestructuringUpdate()));
    }

    [Fact]
    public async Task Cost_ManyKidsHolders_IsLinearAndCancellable()
    {
        // 20.000 holders de /Kids[5 0 R] + 9.999 definições-apelido de 5: antes era O(holders x 10.000)
        // (11,6 s e 15 GB). Agora: Resolve memoizado, recusa no teto e refugo no 1º nó compartilhado.
        byte[] pdf = Samples.PdfWithManyKidsHolders(20_000, 9_999);
        long before = GC.GetTotalAllocatedBytes(true);
        var watch = System.Diagnostics.Stopwatch.StartNew();
        var verdict = await Verdict(pdf);
        watch.Stop();
        long allocated = GC.GetTotalAllocatedBytes(true) - before;

        Assert.Equal(ScanVerdict.NotInspected, verdict);
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(5), $"lento: {watch.Elapsed}");
        Assert.True(allocated < 600L * 1024 * 1024, $"alocou {allocated / 1048576} MB");

        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => Make().ScanAsync("x.pdf", new MemoryStream(pdf), pdf.LongLength, cancellation.Token));
    }

    // ---------------------------------------------------------------- aninhamento profundo (VOLTA r3)
    // Sem a guarda de profundidade, 100.000 níveis derrubam o PROCESSO (stack overflow não é capturável).

    [Theory]
    [InlineData('[', 100_000)]
    [InlineData('<', 100_000)]
    [InlineData('[', 10_000)]
    [InlineData('<', 10_000)]
    [InlineData('[', 65)]
    [InlineData('<', 65)]
    public async Task DeepNesting_IsNotInspected_AndNeverCrashesTheProcess(char kind, int depth)
        => Assert.Equal(ScanVerdict.NotInspected, await Verdict(Samples.PdfWithDeepNesting(kind, depth)));

    [Fact]
    public async Task Nesting_AtTheLimit_StillWorks()
        => Assert.Equal(ScanVerdict.Clean, await Verdict(Samples.PdfWithDeepNesting('[', 40)));

    [Fact]
    public async Task DeepEmbeddedFilesNameTree_DoesNotRecurseWithoutBound()
    {
        // 20.000 nós /Kids encadeados: a recursão do name tree tem de ter teto.
        Assert.Equal(ScanVerdict.NotInspected, await Verdict(Samples.PdfWithDeepNameTree(20_000)));
        Assert.Equal(ScanVerdict.NotInspected, await Verdict(Samples.PdfWithDeepNameTree(66)));

        // Árvore real (poucos níveis) segue válida.
        Assert.Equal(ScanVerdict.Clean, await Verdict(Samples.PdfWithDeepNameTree(5)));
    }

    // ---------------------------------------------------------------- limite de objetos

    [Fact]
    public async Task PdfObjects_BeyondTheOld1024_AreInspectedByDefault()
        => Assert.Equal(ScanVerdict.Clean, await Verdict(Samples.PdfWithManyObjects(3000)));

    [Fact]
    public async Task PdfObjects_LimitIsConfigurable_AndExceedingItIsNotInspected()
    {
        byte[] pdf = Samples.PdfWithManyObjects(500);
        Assert.Equal(ScanVerdict.Clean, await Verdict(pdf, new() { MaxPdfObjects = 500 }));

        var response = await Make(new() { MaxPdfObjects = 499 }).ScanAsync("x.pdf", pdf);
        Assert.Equal(ScanVerdict.NotInspected, response.Verdict);
        Assert.Contains("objetos PDF", response.Reason);
    }

    [Fact]
    public async Task PdfObjects_DoNotUseTheContainerEntriesLimit()
        => Assert.Equal(ScanVerdict.Clean,
            await Verdict(Samples.PdfWithManyObjects(100), new() { MaxContainerEntries = 5 }));

    [Fact]
    public void Options_NewLimits_AreValidated()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => Make(new() { MaxPdfObjects = 0 }));
        Assert.Throws<ArgumentOutOfRangeException>(() => Make(new() { MaxPdfObjects = 1_000_001 }));
    }

    // ---------------------------------------------------------------- binário por papel

    [Fact]
    public async Task BinaryRole_FontFile2WithStrayParenthesis_IsClean()
        => Assert.Equal(ScanVerdict.Clean, await Verdict(Samples.PdfWithFontFile2Binary()));

    [Fact]
    public async Task BinaryRole_IccProfileWithStrayParenthesis_IsClean()
        => Assert.Equal(ScanVerdict.Clean, await Verdict(Samples.PdfWithIccProfileBinary()));

    [Fact]
    public async Task BinaryRole_SameBytesInUnreferencedStream_StillNotInspected()
        => Assert.Equal(ScanVerdict.NotInspected, await Verdict(Samples.PdfWithUnreferencedBinaryStream()));

    [Fact]
    public async Task BinaryRole_ActionNameInsideFontProgram_IsStillFound()
        => Assert.Equal(ScanVerdict.Rejected, await Verdict(Samples.PdfWithFontFile2HidingJavaScript()));

    [Fact]
    public async Task BinaryRole_ObjStmIsNeverTreatedAsBinary()
        => Assert.Equal(ScanVerdict.NotInspected, await Verdict(Samples.PdfWithObjStmReferencedAsFontFile()));

    // ---------------------------------------------------------------- imagens com codec

    [Fact]
    public async Task ImageCodec_DctImageThatIsNotAnAttachment_IsClean()
        => Assert.Equal(ScanVerdict.Clean, await Verdict(Samples.PdfWithJpegImage()));

    [Fact]
    public async Task ImageStream_IsNotDecoded_SoABigRasterDoesNotBlowTheBudget()
    {
        var options = new FileScannerOptions { MaxDecompressedBytesPerStream = 1024 };
        Assert.Equal(ScanVerdict.Clean, await Verdict(Samples.PdfWithLargeFlateImage(256 * 1024), options));

        // Mesmo conteúdo fora de /Subtype /Image, ou como anexo, continua sendo decodificado e barrado.
        Assert.Equal(ScanVerdict.NotInspected, await Verdict(Samples.PdfWithLargeFlateNonImage(256 * 1024), options));
        Assert.Equal(ScanVerdict.NotInspected, await Verdict(Samples.PdfWithLargeFlateImageAsAttachment(256 * 1024), options));
    }

    [Fact]
    public async Task ImageCodec_DctOnANonImageStream_StillNotInspected()
        => Assert.Equal(ScanVerdict.NotInspected, await Verdict(Samples.PdfWithDctOnNonImageStream()));

    [Fact]
    public async Task ImageCodec_DctOnAnEmbeddedFile_StillNotInspected()
        => Assert.Equal(ScanVerdict.NotInspected, await Verdict(Samples.PdfWithDctEmbeddedFile()));
}
