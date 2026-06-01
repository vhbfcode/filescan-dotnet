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
}
