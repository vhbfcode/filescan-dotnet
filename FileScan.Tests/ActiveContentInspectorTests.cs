using FileScan.Scanning;
using Xunit;

namespace FileScan.Tests;

public class ActiveContentInspectorTests
{
    [Fact]
    public void CleanPdf_HasNoFindings_AndIsFullyInspected()
    {
        var r = ActiveContentInspector.Inspect("x.pdf", Samples.CleanPdf());
        Assert.Empty(r.Findings);
        Assert.True(r.FullyInspected);
    }

    [Fact]
    public void PdfWithJavaScript_IsDetected()
        => Assert.NotEmpty(ActiveContentInspector.Inspect("x.pdf", Samples.PdfWithJavaScript()).Findings);

    [Fact]
    public void PdfFontSubset_IsNotFalsePositive()
        => Assert.Empty(ActiveContentInspector.Inspect("x.pdf", Samples.PdfWithFontSubsetOnly()).Findings);

    [Fact]
    public void DocxWithDde_IsDetected()
        => Assert.NotEmpty(ActiveContentInspector.Inspect("x.docx", Samples.DocxWithDde()).Findings);

    [Fact]
    public void DocxWithImageBytesContainingPercent_IsNotFalsePositive()
    {
        var r = ActiveContentInspector.Inspect("x.docx", Samples.DocxWithImageContainingPercentBytes());
        Assert.Empty(r.Findings);
        Assert.True(r.FullyInspected);
    }

    [Fact]
    public void CsvFormulaInjection_IsDetected()
        => Assert.NotEmpty(ActiveContentInspector.Inspect("x.csv", Samples.CsvInjection()).Findings);

    [Fact]
    public void CsvNegativeNumbers_AreNotFalsePositive()
        => Assert.Empty(ActiveContentInspector.Inspect("x.csv", Samples.CsvCleanNegatives()).Findings);

    [Fact]
    public void PngWithScript_IsDetected()
        => Assert.NotEmpty(ActiveContentInspector.Inspect("x.png", Samples.PngWithScript()).Findings);

    [Fact]
    public void PngWithPercentTag_IsNotFalsePositive()
        => Assert.Empty(ActiveContentInspector.Inspect("x.png", Samples.PngWithPercentTag()).Findings);

    [Fact]
    public void CleanPng_IsNotFalsePositive()
        => Assert.Empty(ActiveContentInspector.Inspect("x.png", Samples.CleanPng()).Findings);

    // --- Hex-encoding evasion tests ---

    [Fact]
    public void PdfWithHexEncodedJs_IsDetected()
        // /J#53 deve ser decodificado para /JS e detectado
        => Assert.NotEmpty(ActiveContentInspector.Inspect("x.pdf", Samples.PdfWithHexEncodedJs()).Findings);

    [Fact]
    public void PdfWithPartiallyHexEncodedJavaScript_IsDetected()
        // /Java#53cript deve ser decodificado para /JavaScript e detectado
        => Assert.NotEmpty(ActiveContentInspector.Inspect("x.pdf", Samples.PdfWithPartiallyHexEncodedJavaScript()).Findings);

    [Fact]
    public void PdfWithFullyHexEncodedJavaScript_IsDetected()
        // /#4AavaScript deve ser decodificado para /JavaScript e detectado (sem /JS auxiliar)
        => Assert.NotEmpty(ActiveContentInspector.Inspect("x.pdf", Samples.PdfWithFullyHexEncodedJavaScript()).Findings);

    [Fact]
    public void PdfWithHexEncodedLaunch_IsDetected()
        // /L#61unch deve ser decodificado para /Launch e detectado
        => Assert.NotEmpty(ActiveContentInspector.Inspect("x.pdf", Samples.PdfWithHexEncodedLaunch()).Findings);

    [Fact]
    public void PdfWithJavaScript_PlainEncoding_StillDetected()
        // Regressão: /JavaScript literal continua sendo detectado após a mudança
        => Assert.NotEmpty(ActiveContentInspector.Inspect("x.pdf", Samples.PdfWithJavaScript()).Findings);

    [Fact]
    public void PdfWithHashInBinaryStream_IsNotFalsePositive()
        // '#' fora de um nome PDF não deve ser decodificado e não deve gerar FP
        => Assert.Empty(ActiveContentInspector.Inspect("x.pdf", Samples.PdfWithHashInBinaryStream()).Findings);

    // --- Segmentação stream × estrutural (bug real: FP em bytes comprimidos) ---

    [Fact]
    public void PdfWithCompressedNoiseLookingLikeJs_IsNotFalsePositive_ButIsIncomplete()
    {
        // Bytes comprimidos (não interpretáveis) contendo "/JS" e "/#4A#53" por acaso: o corpo do
        // stream declara /Filter e não descomprime — não pode ser julgado cru (era o FP relatado).
        // E corpo ilegível com /Filter declarado também NÃO é inspeção integral (Frente B2).
        var r = ActiveContentInspector.Inspect("x.pdf", Samples.PdfWithCompressedNoiseLookingLikeJs());
        Assert.Empty(r.Findings);
        Assert.False(r.FullyInspected);
    }

    [Fact]
    public void PdfWithJavaScriptOnlyInsideFlateStream_IsDetected()
    {
        // O marcador existe SÓ dentro do stream FlateDecode: exige descomprimir e varrer o inflado
        var result = ActiveContentInspector.Inspect("x.pdf", Samples.PdfWithJavaScriptOnlyInsideFlateStream());
        Assert.True(result.Findings.Count > 0, string.Join(" | ", result.Incomplete));
    }

    [Fact]
    public void PdfWithJavaScriptInUnfilteredStream_IsDetected()
        // Stream sem /Filter é literal: o corpo cru continua varrido
        => Assert.NotEmpty(ActiveContentInspector.Inspect("x.pdf", Samples.PdfWithJavaScriptInUnfilteredStream()).Findings);

    [Fact]
    public void PdfTruncatedStream_MarkerAfterStreamKeyword_IsDetected_AndIncomplete()
    {
        // "stream" truncado: falha para o lado da detecção (varre o restante) E sinaliza
        // estrutura inválida — nunca "Clean por não ter conseguido olhar".
        var r = ActiveContentInspector.Inspect("x.pdf", Samples.PdfTruncatedStreamWithJavaScriptAfter());
        Assert.NotEmpty(r.Findings);
        Assert.False(r.FullyInspected);
    }

    [Fact]
    public void PdfWithInvalidHashEscapeInName_NoCrash_NoFalsePositive()
        // '#' dentro de nome sem dois hex-dígitos deve ser copiado literalmente: sem crash, sem FP
        => Assert.Empty(ActiveContentInspector.Inspect("x.pdf", Samples.PdfWithInvalidHashEscapeInName()).Findings);

    // --- Frente B1: contexto lexical — texto inerte NÃO é ação ---

    [Fact]
    public void MarkerOnlyInLiteralString_IsNotFalsePositive()
    {
        var r = ActiveContentInspector.Inspect("x.pdf", Samples.PdfWithMarkerOnlyInLiteralString());
        Assert.Empty(r.Findings);
        Assert.True(r.FullyInspected);
    }

    [Fact]
    public void MarkerOnlyInComment_IsNotFalsePositive()
    {
        var r = ActiveContentInspector.Inspect("x.pdf", Samples.PdfWithMarkerOnlyInComment());
        Assert.Empty(r.Findings);
        Assert.True(r.FullyInspected);
    }

    [Fact]
    public void MarkerInPageText_UncompressedContentStream_IsNotFalsePositive()
    {
        var r = ActiveContentInspector.Inspect("x.pdf", Samples.PdfWithMarkerInPageTextUncompressed());
        Assert.Empty(r.Findings);
        Assert.True(r.FullyInspected);
    }

    [Fact]
    public void MarkerInPageText_FlateContentStream_IsNotFalsePositive()
    {
        var r = ActiveContentInspector.Inspect("x.pdf", Samples.PdfWithMarkerInPageTextFlate());
        Assert.Empty(r.Findings);
        Assert.True(r.FullyInspected);
    }

    [Fact]
    public void EndstreamBytesInsideMeasuredBody_IsBenign_AndFullyInspected()
    {
        // Só o parse de /Length mantém a segmentação alinhada quando o corpo contém "endstream";
        // sabotar de volta a busca textual corta o zlib no meio e derruba este teste.
        var r = ActiveContentInspector.Inspect("x.pdf", Samples.PdfWithEndstreamBytesInsideMeasuredStream());
        Assert.Empty(r.Findings);
        Assert.True(r.FullyInspected);
    }

    [Fact]
    public void JsHiddenAfterDeclaredLength_IsIncomplete()
    {
        // /Length mentiroso invalida a estrutura; não é aceito como Clean.
        var result = ActiveContentInspector.Inspect("x.pdf", Samples.PdfHidingJsAfterDeclaredLength());
        Assert.False(result.FullyInspected);
    }

    // --- Frente B2: corpo não inspecionável nunca é "integralmente inspecionado" ---

    [Fact]
    public void UnsupportedFilter_HidingJs_IsIncomplete_NotSilentlyIgnored()
    {
        var r = ActiveContentInspector.Inspect("x.pdf", Samples.PdfWithLzwFilteredStreamHidingJs());
        Assert.Empty(r.Findings);       // bytes codificados não são julgados crus (sem FP)...
        Assert.False(r.FullyInspected); // ...mas o corpo ilegível NÃO passa como inspecionado
    }

    [Fact]
    public void EncryptedPdf_IsIncomplete()
        => Assert.False(ActiveContentInspector.Inspect("x.pdf", Samples.PdfEncrypted()).FullyInspected);

    [Fact]
    public void TruncatedPdf_NoEof_IsIncomplete()
        => Assert.False(ActiveContentInspector.Inspect("x.pdf", Samples.PdfTruncatedNoEof()).FullyInspected);

    [Fact]
    public void IncrementalUpdateTruncatedAfterIntermediateEof_IsIncomplete()
        // F2: o %%EOF tem de estar na CAUDA do arquivo — um %%EOF de update incremental anterior
        // não prova que a cauda não foi truncada. Sabotagem (IndexOf global) derruba este teste.
        => Assert.False(ActiveContentInspector.Inspect("x.pdf", Samples.PdfTruncatedAfterIntermediateEof()).FullyInspected);

    [Fact]
    public void Ole2BestEffort_IncompleteIsEmptyByConstruction_DocumentedScope()
    {
        // F1 (pin de contrato, rota a): OLE2 não alimenta Incomplete — a varredura é best-effort e
        // a garantia "inspeção integral ⇒ Clean" está ESCOPADA a PDF/OOXML na documentação
        // (ScanVerdict.Clean, READMEs, SECURITY.md). Se este teste falhar porque OLE2 passou a
        // emitir Incomplete (rota b do F1), atualize o escopo documentado nas 3 fontes.
        var r = ActiveContentInspector.Inspect("legado.doc", Samples.Ole2WithoutVisibleMarkers());
        Assert.Empty(r.Findings);
        Assert.True(r.FullyInspected);
    }

    [Fact]
    public void DecompressionCapExceeded_IsIncomplete()
    {
        var pdf = Samples.PdfWithLargeFlateStream(64 * 1024);
        var r = ActiveContentInspector.Inspect("x.pdf", pdf, maxDecompressedBytesPerStream: 1024);
        Assert.False(r.FullyInspected);
    }

    [Fact]
    public void DecompressionUnderCap_IsFullyInspected()
    {
        // Regressão do falso achado "caso 14": cap NÃO excedido ⇒ inspeção integral (Clean correto).
        var pdf = Samples.PdfWithLargeFlateStream(64 * 1024);
        var r = ActiveContentInspector.Inspect("x.pdf", pdf);
        Assert.Empty(r.Findings);
        Assert.True(r.FullyInspected);
    }
}
