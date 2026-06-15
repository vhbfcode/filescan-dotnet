using FileScan.Scanning;
using Xunit;

namespace FileScan.Tests;

public class ActiveContentInspectorTests
{
    [Fact]
    public void CleanPdf_HasNoFindings()
        => Assert.Empty(ActiveContentInspector.Inspect("x.pdf", Samples.CleanPdf()));

    [Fact]
    public void PdfWithJavaScript_IsDetected()
        => Assert.NotEmpty(ActiveContentInspector.Inspect("x.pdf", Samples.PdfWithJavaScript()));

    [Fact]
    public void PdfFontSubset_IsNotFalsePositive()
        => Assert.Empty(ActiveContentInspector.Inspect("x.pdf", Samples.PdfWithFontSubsetOnly()));

    [Fact]
    public void DocxWithDde_IsDetected()
        => Assert.NotEmpty(ActiveContentInspector.Inspect("x.docx", Samples.DocxWithDde()));

    [Fact]
    public void DocxWithImageBytesContainingPercent_IsNotFalsePositive()
        => Assert.Empty(ActiveContentInspector.Inspect("x.docx", Samples.DocxWithImageContainingPercentBytes()));

    [Fact]
    public void CsvFormulaInjection_IsDetected()
        => Assert.NotEmpty(ActiveContentInspector.Inspect("x.csv", Samples.CsvInjection()));

    [Fact]
    public void CsvNegativeNumbers_AreNotFalsePositive()
        => Assert.Empty(ActiveContentInspector.Inspect("x.csv", Samples.CsvCleanNegatives()));

    [Fact]
    public void PngWithScript_IsDetected()
        => Assert.NotEmpty(ActiveContentInspector.Inspect("x.png", Samples.PngWithScript()));

    [Fact]
    public void PngWithPercentTag_IsNotFalsePositive()
        => Assert.Empty(ActiveContentInspector.Inspect("x.png", Samples.PngWithPercentTag()));

    [Fact]
    public void CleanPng_IsNotFalsePositive()
        => Assert.Empty(ActiveContentInspector.Inspect("x.png", Samples.CleanPng()));

    // --- Hex-encoding evasion tests ---

    [Fact]
    public void PdfWithHexEncodedJs_IsDetected()
        // /J#53 deve ser decodificado para /JS e detectado
        => Assert.NotEmpty(ActiveContentInspector.Inspect("x.pdf", Samples.PdfWithHexEncodedJs()));

    [Fact]
    public void PdfWithPartiallyHexEncodedJavaScript_IsDetected()
        // /Java#53cript deve ser decodificado para /JavaScript e detectado
        => Assert.NotEmpty(ActiveContentInspector.Inspect("x.pdf", Samples.PdfWithPartiallyHexEncodedJavaScript()));

    [Fact]
    public void PdfWithFullyHexEncodedJavaScript_IsDetected()
        // /#4AavaScript deve ser decodificado para /JavaScript e detectado (sem /JS auxiliar)
        => Assert.NotEmpty(ActiveContentInspector.Inspect("x.pdf", Samples.PdfWithFullyHexEncodedJavaScript()));

    [Fact]
    public void PdfWithHexEncodedLaunch_IsDetected()
        // /L#61unch deve ser decodificado para /Launch e detectado
        => Assert.NotEmpty(ActiveContentInspector.Inspect("x.pdf", Samples.PdfWithHexEncodedLaunch()));

    [Fact]
    public void PdfWithJavaScript_PlainEncoding_StillDetected()
        // Regressão: /JavaScript literal continua sendo detectado após a mudança
        => Assert.NotEmpty(ActiveContentInspector.Inspect("x.pdf", Samples.PdfWithJavaScript()));

    [Fact]
    public void PdfWithHashInBinaryStream_IsNotFalsePositive()
        // '#' fora de um nome PDF não deve ser decodificado e não deve gerar FP
        => Assert.Empty(ActiveContentInspector.Inspect("x.pdf", Samples.PdfWithHashInBinaryStream()));

    [Fact]
    public void PdfWithInvalidHashEscapeInName_NoCrash_NoFalsePositive()
        // '#' dentro de nome sem dois hex-dígitos deve ser copiado literalmente: sem crash, sem FP
        => Assert.Empty(ActiveContentInspector.Inspect("x.pdf", Samples.PdfWithInvalidHashEscapeInName()));
}
