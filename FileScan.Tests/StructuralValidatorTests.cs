using FileScan.Scanning;
using Xunit;

namespace FileScan.Tests;

public class StructuralValidatorTests
{
    private static StructuralValidator Make(params string[] allowedExtensions)
        => new(new FileScannerOptions
        {
            AllowedExtensions = allowedExtensions,
            MaxFileSizeBytes = 25 * 1024 * 1024,
        });

    [Fact]
    public void OptionsMutatedAfterConstruction_DoNotChangeStructuralPolicy()
    {
        var options = new FileScannerOptions { AllowedExtensions = ["pdf"] };
        var validator = new StructuralValidator(options);
        options.AllowedExtensions = ["txt"];
        options.MaxFileSizeBytes = 1;

        Assert.Null(validator.Validate("x.pdf", Samples.CleanPdf()));
        Assert.Contains("não permitida", validator.Validate("x.txt", Samples.CleanPdf()));
    }

    [Fact]
    public void CleanPdf_Passes()
        => Assert.Null(Make().Validate("x.pdf", Samples.CleanPdf()));

    [Fact]
    public void DisguisedExecutable_IsRejected()
        => Assert.NotNull(Make().Validate("photo.jpg", Samples.ExeBytes()));

    [Fact]
    public void TypeMismatch_PngNamedPdf_IsRejected()
        => Assert.NotNull(Make().Validate("doc.pdf", Samples.CleanPng()));

    [Fact]
    public void ExtensionNotInAllowlist_IsRejected()
        => Assert.NotNull(Make("pdf").Validate("data.txt", [1, 2, 3, 4, 5]));

    [Fact]
    public void EmptyFile_IsRejected()
        => Assert.NotNull(Make().Validate("x.pdf", []));

    [Fact]
    public void DangerousContentType_DetectsExecutable()
        => Assert.NotNull(Make().DangerousContentType(Samples.ExeBytes()));

    [Fact]
    public void DangerousContentType_NullForPdf()
        => Assert.Null(Make().DangerousContentType(Samples.CleanPdf()));
}
