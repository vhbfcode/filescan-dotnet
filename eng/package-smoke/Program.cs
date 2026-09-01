using System.IO.Compression;
using System.Text;
using FileScan.Scanning;

static byte[] Pdf(string catalog)
{
    var objects = new[]
    {
        $"<</Type/Catalog/Pages 2 0 R{catalog}>>",
        "<</Type/Pages/Kids[]/Count 0>>",
    };
    using var output = new MemoryStream();
    var offsets = new List<long>();
    Write("%PDF-1.7\n");
    for (int index = 0; index < objects.Length; index++)
    {
        offsets.Add(output.Position);
        Write($"{index + 1} 0 obj\n{objects[index]}\nendobj\n");
    }
    long xref = output.Position;
    Write("xref\n0 3\n0000000000 65535 f \n");
    foreach (long offset in offsets) Write($"{offset:0000000000} 00000 n \n");
    Write($"trailer\n<</Size 3/Root 1 0 R>>\nstartxref\n{xref}\n%%EOF\n");
    return output.ToArray();

    void Write(string text)
    {
        byte[] bytes = Encoding.ASCII.GetBytes(text);
        output.Write(bytes, 0, bytes.Length);
    }
}

static byte[] PdfWithFileSpecEfExecutableWithoutType()
{
    byte[] executable =
    [
        0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF,
        .. Encoding.ASCII.GetBytes("  harmless synthetic PE-shaped fixture  ")
    ];
    using var output = new MemoryStream();
    var offsets = new List<long>();
    Write("%PDF-1.7\n");
    Object(1, "<</Type/Catalog/Pages 2 0 R/Names<</EmbeddedFiles<</Names[(payload.exe) 3 0 R]>>>>>>");
    Object(2, "<</Type/Pages/Kids[]/Count 0>>");
    Object(3, "<</Type/Filespec/F(payload.exe)/EF<</F 4 0 R>>>>");
    offsets.Add(output.Position);
    Write($"4 0 obj\n<</Length {executable.Length}>>\nstream\n");
    output.Write(executable);
    Write("\nendstream\nendobj\n");
    long xref = output.Position;
    Write("xref\n0 5\n0000000000 65535 f \n");
    foreach (long offset in offsets) Write($"{offset:0000000000} 00000 n \n");
    Write($"trailer\n<</Size 5/Root 1 0 R>>\nstartxref\n{xref}\n%%EOF\n");
    return output.ToArray();

    void Object(int number, string dictionary)
    {
        offsets.Add(output.Position);
        Write($"{number} 0 obj\n{dictionary}\nendobj\n");
    }

    void Write(string text) => output.Write(Encoding.ASCII.GetBytes(text));
}

static byte[] PdfGraph(params (int Number, byte[] Body)[] source)
{
    var objects = source.OrderBy(item => item.Number).ToArray();
    int maxObject = objects.Max(item => item.Number);
    var offsets = new Dictionary<int, long>();
    using var output = new MemoryStream();
    Write(Encoding.ASCII.GetBytes("%PDF-1.7\n"));
    foreach (var item in objects)
    {
        offsets[item.Number] = output.Position;
        Write(Encoding.ASCII.GetBytes($"{item.Number} 0 obj\n"));
        Write(item.Body);
        Write(Encoding.ASCII.GetBytes("\nendobj\n"));
    }

    long xref = output.Position;
    Write(Encoding.ASCII.GetBytes($"xref\n0 {maxObject + 1}\n0000000000 65535 f \n"));
    for (int number = 1; number <= maxObject; number++)
    {
        string entry = offsets.TryGetValue(number, out long offset)
            ? $"{offset:0000000000} 00000 n \n"
            : "0000000000 65535 f \n";
        Write(Encoding.ASCII.GetBytes(entry));
    }
    Write(Encoding.ASCII.GetBytes(
        $"trailer\n<</Size {maxObject + 1}/Root 1 0 R>>\nstartxref\n{xref}\n%%EOF\n"));
    return output.ToArray();

    void Write(byte[] bytes) => output.Write(bytes);
}

static byte[] PdfStreamBody(byte[] body) =>
[
    .. Encoding.ASCII.GetBytes($"<</Length {body.Length}>>\nstream\n"),
    .. body,
    .. Encoding.ASCII.GetBytes("\nendstream"),
];

static byte[] PdfWithEmbeddedFilesScalarValue() => PdfGraph(
    (1, Encoding.ASCII.GetBytes(
        "<</Type/Catalog/Pages 2 0 R/Names<</EmbeddedFiles<</Names[(payload.exe) 42]>>>>>>")),
    (2, Encoding.ASCII.GetBytes("<</Type/Pages/Kids[]/Count 0>>")));

static byte[] PdfWithEmbeddedFilesDirectStream() => PdfGraph(
    (1, Encoding.ASCII.GetBytes(
        "<</Type/Catalog/Pages 2 0 R/Names<</EmbeddedFiles<</Names[(payload.exe) 4 0 R]>>>>>>")),
    (2, Encoding.ASCII.GetBytes("<</Type/Pages/Kids[]/Count 0>>")),
    (4, PdfStreamBody(
    [
        0x4D, 0x5A, 0x90, 0x00,
        .. Encoding.ASCII.GetBytes("  direct stream is not a FileSpec  "),
    ])));

static byte[] PdfWithEmbeddedFilesChildMissingLimits() => PdfGraph(
    (1, Encoding.ASCII.GetBytes(
        "<</Type/Catalog/Pages 2 0 R/Names<</EmbeddedFiles 3 0 R>>>>")),
    (2, Encoding.ASCII.GetBytes("<</Type/Pages/Kids[]/Count 0>>")),
    (3, Encoding.ASCII.GetBytes("<</Kids[4 0 R]>>")),
    (4, Encoding.ASCII.GetBytes("<</Names[(a)(a.txt)]>>")));

static byte[] PdfWithEmbeddedFilesDirectKid() => PdfGraph(
    (1, Encoding.ASCII.GetBytes(
        "<</Type/Catalog/Pages 2 0 R/Names<</EmbeddedFiles<</Kids[<</Names[(a)(a.txt)]/Limits[(a)(a)]>>]>>>>>>")),
    (2, Encoding.ASCII.GetBytes("<</Type/Pages/Kids[]/Count 0>>")));

static byte[] PdfWithEmbeddedFilesIntermediateMissingLimits() => PdfGraph(
    (1, Encoding.ASCII.GetBytes(
        "<</Type/Catalog/Pages 2 0 R/Names<</EmbeddedFiles 3 0 R>>>>")),
    (2, Encoding.ASCII.GetBytes("<</Type/Pages/Kids[]/Count 0>>")),
    (3, Encoding.ASCII.GetBytes("<</Kids[4 0 R]>>")),
    (4, Encoding.ASCII.GetBytes("<</Kids[5 0 R]>>")),
    (5, Encoding.ASCII.GetBytes("<</Names[(a)(a.txt)]/Limits[(a)(a)]>>")));

static byte[] PdfWithEmbeddedFilesValidIndirectKid() => PdfGraph(
    (1, Encoding.ASCII.GetBytes(
        "<</Type/Catalog/Pages 2 0 R/Names<</EmbeddedFiles 3 0 R>>>>")),
    (2, Encoding.ASCII.GetBytes("<</Type/Pages/Kids[]/Count 0>>")),
    (3, Encoding.ASCII.GetBytes("<</Kids[4 0 R]>>")),
    (4, Encoding.ASCII.GetBytes("<</Names[(a)(a.txt)]/Limits[(a)(a)]>>")));

static byte[] PdfWithEmbeddedFilesRootKidsAndLimits() => PdfGraph(
    (1, Encoding.ASCII.GetBytes(
        "<</Type/Catalog/Pages 2 0 R/Names<</EmbeddedFiles 3 0 R>>>>")),
    (2, Encoding.ASCII.GetBytes("<</Type/Pages/Kids[]/Count 0>>")),
    (3, Encoding.ASCII.GetBytes("<</Kids[4 0 R]/Limits[(a)(a)]>>")),
    (4, Encoding.ASCII.GetBytes("<</Names[(a)(a.txt)]/Limits[(a)(a)]>>")));

static byte[] PdfWithEmbeddedFilesHexStringKeyAndLimits() => PdfGraph(
    (1, Encoding.ASCII.GetBytes(
        "<</Type/Catalog/Pages 2 0 R/Names<</EmbeddedFiles 3 0 R>>>>")),
    (2, Encoding.ASCII.GetBytes("<</Type/Pages/Kids[]/Count 0>>")),
    (3, Encoding.ASCII.GetBytes("<</Kids[4 0 R]>>")),
    (4, Encoding.ASCII.GetBytes("<</Names[<61>(a.txt)]/Limits[<61><61>]>>")));

static byte[] PdfWithUnrelatedCustomFsKey() => PdfGraph(
    (1, Encoding.ASCII.GetBytes("<</Type/Catalog/Pages 2 0 R/Acme<</FS 3 0 R>>>>")),
    (2, Encoding.ASCII.GetBytes("<</Type/Pages/Kids[]/Count 0>>")),
    (3, Encoding.ASCII.GetBytes("<</F(payload.exe)/EF<</F 4 0 R>>>>")),
    (4, PdfStreamBody(
    [
        0x4D, 0x5A, 0x90, 0x00,
        .. Encoding.ASCII.GetBytes("  unrelated custom dictionary payload  "),
    ])));

static byte[] OoxmlWithOversizedEntryBeforeDde()
{
    using var output = new MemoryStream();
    using (var zip = new ZipArchive(output, ZipArchiveMode.Create, leaveOpen: true))
    {
        using (var oversized = zip.CreateEntry("word/oversized.bin").Open())
            oversized.Write(new byte[2048]);

        using var writer = new StreamWriter(zip.CreateEntry("word/document.xml").Open());
        writer.Write("<w:instrText>DDEAUTO cmd.exe</w:instrText>");
    }
    return output.ToArray();
}

static byte[] PdfWithJavaScriptInRealObjectStream()
{
    static byte[] Bytes(string value) => Encoding.ASCII.GetBytes(value);
    byte[] objectStreamBody = Bytes("7 0 <</S/JavaScript/JS(app.alert\\('x'\\))>>");
    using var compressed = new MemoryStream();
    using (var zlib = new ZLibStream(compressed, CompressionLevel.Optimal, leaveOpen: true))
        zlib.Write(objectStreamBody);
    byte[] streamBody = compressed.ToArray();
    var offsets = new Dictionary<int, long>();
    using var output = new MemoryStream();

    Write(Bytes("%PDF-1.7\n%\xE2\xE3\xCF\xD3\n"));
    WriteObject(1, Bytes("<</Type/Catalog/Pages 2 0 R/OpenAction 7 0 R>>"));
    WriteObject(2, Bytes("<</Type/Pages/Kids[]/Count 0>>"));
    WriteObject(4,
    [
        .. Bytes($"<</Type/ObjStm/N 1/First 4/Filter/FlateDecode/Length {streamBody.Length}>>\nstream\n"),
        .. streamBody,
        .. Bytes("\nendstream"),
    ]);

    long xrefOffset = output.Position;
    offsets[5] = xrefOffset;
    byte[] xref = new byte[8 * 7];
    Xref(0, 0, 0, 65535);
    Xref(1, 1, offsets[1], 0);
    Xref(2, 1, offsets[2], 0);
    Xref(3, 0, 0, 0);
    Xref(4, 1, offsets[4], 0);
    Xref(5, 1, offsets[5], 0);
    Xref(6, 0, 0, 0);
    Xref(7, 2, 4, 0);
    Write(Bytes($"5 0 obj\n<</Type/XRef/Size 8/Root 1 0 R/W[1 4 2]/Index[0 8]/Length {xref.Length}>>\nstream\n"));
    Write(xref);
    Write(Bytes($"\nendstream\nendobj\nstartxref\n{xrefOffset}\n%%EOF\n"));
    return output.ToArray();

    void Write(byte[] value) => output.Write(value);
    void WriteObject(int number, byte[] body)
    {
        offsets[number] = output.Position;
        Write(Bytes($"{number} 0 obj\n"));
        Write(body);
        Write(Bytes("\nendobj\n"));
    }
    void Xref(int index, byte type, long field1, int field2)
    {
        int offset = index * 7;
        xref[offset] = type;
        xref[offset + 1] = (byte)(field1 >> 24);
        xref[offset + 2] = (byte)(field1 >> 16);
        xref[offset + 3] = (byte)(field1 >> 8);
        xref[offset + 4] = (byte)field1;
        xref[offset + 5] = (byte)(field2 >> 8);
        xref[offset + 6] = (byte)field2;
    }
}

var scanner = new FileScanService(new FileScannerOptions());
var clean = await scanner.ScanAsync("clean.pdf", Pdf(string.Empty));
var active = await scanner.ScanAsync("active.pdf",
    Pdf("/OpenAction<</S/JavaScript/JS(app.alert('x'))>>"));
var flagged = await new FileScanService(new FileScannerOptions
{
    OnActiveContent = ActiveContentAction.Flag,
}).ScanAsync("flagged.pdf", Pdf("/OpenAction<</S/JavaScript/JS(app.alert('x'))>>"));
var ignored = await new FileScanService(new FileScannerOptions
{
    OnActiveContent = ActiveContentAction.Ignore,
}).ScanAsync("ignored.pdf", Pdf(string.Empty));
var trailingBytes = await scanner.ScanAsync("trailing.pdf",
    [.. Pdf(string.Empty), .. Encoding.ASCII.GetBytes("non-whitespace")]);
byte[] fileSpecAttachment = PdfWithFileSpecEfExecutableWithoutType();
var omittedEmbeddedType = await scanner.ScanAsync("attachment.pdf", fileSpecAttachment);
var unrelatedEf = await scanner.ScanAsync("unrelated-ef.pdf", Pdf("/EF 42"));
var malformedEmbeddedScalar = await scanner.ScanAsync(
    "malformed-embedded-scalar.pdf", PdfWithEmbeddedFilesScalarValue());
var malformedEmbeddedStream = await scanner.ScanAsync(
    "malformed-embedded-stream.pdf", PdfWithEmbeddedFilesDirectStream());
var unrelatedFs = await scanner.ScanAsync("unrelated-fs.pdf", PdfWithUnrelatedCustomFsKey());
var malformedNameTreeKey = await scanner.ScanAsync("name-tree-key.pdf",
    Pdf("/Names<</EmbeddedFiles<</Names[42(relative/manual.txt)]>>>>"));
var outOfOrderNameTree = await scanner.ScanAsync("name-tree-order.pdf",
    Pdf("/Names<</EmbeddedFiles<</Names[(z)(z.txt)(a)(a.txt)]>>>>"));
var invalidNameTreeLimits = await scanner.ScanAsync("name-tree-limits.pdf",
    Pdf("/Names<</EmbeddedFiles<</Names[(a)(a.txt)]/Limits[(b)(b)]>>>>"));
var rootNamesWithLimits = await scanner.ScanAsync("name-tree-root-names-limits.pdf",
    Pdf("/Names<</EmbeddedFiles<</Names[(a)(a.txt)]/Limits[(a)(a)]>>>>"));
var rootKidsWithLimits = await scanner.ScanAsync("name-tree-root-kids-limits.pdf",
    PdfWithEmbeddedFilesRootKidsAndLimits());
var hexStringKey = await scanner.ScanAsync("name-tree-hex-key.pdf",
    Pdf("/Names<</EmbeddedFiles<</Names[<61>(a.txt)]>>>>"));
var hexStringKeyAndLimits = await scanner.ScanAsync("name-tree-hex-key-limits.pdf",
    PdfWithEmbeddedFilesHexStringKeyAndLimits());
var mixedLiteralAndHexKeys = await scanner.ScanAsync("name-tree-mixed-keys.pdf",
    Pdf("/Names<</EmbeddedFiles<</Names[(a)(a.txt)<62>(b.txt)]>>>>"));
var mixedLiteralAndHexDuplicate = await scanner.ScanAsync("name-tree-mixed-duplicate.pdf",
    Pdf("/Names<</EmbeddedFiles<</Names[(a)(a.txt)<61>(duplicate.txt)]>>>>"));
var missingChildLimits = await scanner.ScanAsync("name-tree-child-limits.pdf",
    PdfWithEmbeddedFilesChildMissingLimits());
var directNameTreeKid = await scanner.ScanAsync("name-tree-direct-kid.pdf",
    PdfWithEmbeddedFilesDirectKid());
var missingIntermediateLimits = await scanner.ScanAsync("name-tree-intermediate-limits.pdf",
    PdfWithEmbeddedFilesIntermediateMissingLimits());
var validIndirectKid = await scanner.ScanAsync("name-tree-valid-kid.pdf",
    PdfWithEmbeddedFilesValidIndirectKid());
var unrelatedEmbeddedFiles = await scanner.ScanAsync("unrelated-embedded-files.pdf",
    Pdf("/Acme<</EmbeddedFiles 42>>"));
var exhaustedOoxml = await new FileScanService(new FileScannerOptions
{
    MaxDecompressedBytesPerStream = 1024,
    MaxTotalDecompressedBytes = 1500,
}).ScanAsync("exhausted.docx", OoxmlWithOversizedEntryBeforeDde());
var antivirusClean = await new FileScanService(
    new FileScannerOptions(), virusScanner: new CleanReasonVirus())
    .ScanAsync("antivirus-clean.pdf", Pdf(string.Empty));
bool divergentStructuralPolicyRejected = false;
try
{
    _ = new FileScanService(
        new FileScannerOptions { AllowedExtensions = ["pdf"] },
        new StructuralValidator(new FileScannerOptions()));
}
catch (ArgumentException)
{
    divergentStructuralPolicyRejected = true;
}
var realObjectStream = await scanner.ScanAsync("object-stream.pdf",
    PdfWithJavaScriptInRealObjectStream());
var mutableOptions = new FileScannerOptions();
var mutableScanner = new FileScanService(mutableOptions);
var beforeMutation = await mutableScanner.ScanAsync("before-mutation.pdf", fileSpecAttachment);
mutableOptions.MaxDecompressedBytesPerStream = long.MaxValue;
mutableOptions.MaxTotalDecompressedBytes = long.MaxValue;
mutableOptions.OnActiveContent = ActiveContentAction.Ignore;
var afterMutation = await mutableScanner.ScanAsync("after-mutation.pdf", fileSpecAttachment);
var structuralOptions = new FileScannerOptions { AllowedExtensions = ["pdf"] };
var structuralValidator = new StructuralValidator(structuralOptions);
structuralOptions.AllowedExtensions = ["txt"];
structuralOptions.MaxFileSizeBytes = 1;
string? structuralPdfReason = structuralValidator.Validate("x.pdf", Pdf(string.Empty));
string? structuralTxtReason = structuralValidator.Validate("x.txt", Pdf(string.Empty));
using var cancellation = new CancellationTokenSource();
using var cancelAtEof = new CancelAtEofStream(fileSpecAttachment, cancellation);
bool cancellationPropagated = false;
try
{
    await scanner.ScanAsync("canceled.pdf", cancelAtEof, cancelAtEof.Length, cancellation.Token);
}
catch (OperationCanceledException) when (cancellation.IsCancellationRequested)
{
    cancellationPropagated = true;
}

if (clean.Verdict != ScanVerdict.Clean || clean.Warnings is { Count: > 0 })
    throw new InvalidOperationException($"Clean contract failed: {clean}");
if (active.Verdict != ScanVerdict.Rejected)
    throw new InvalidOperationException($"Active-content contract failed: {active}");
if (flagged.Verdict != ScanVerdict.ActiveContentDetected || flagged.Warnings is not { Count: > 0 })
    throw new InvalidOperationException($"Flag contract failed: {flagged}");
if (ignored.Verdict != ScanVerdict.NotInspected)
    throw new InvalidOperationException($"Ignore contract failed: {ignored}");
if (trailingBytes.Verdict != ScanVerdict.NotInspected)
    throw new InvalidOperationException($"Strict EOF contract failed: {trailingBytes}");
if (omittedEmbeddedType.Verdict != ScanVerdict.Rejected)
    throw new InvalidOperationException($"FileSpec/EF contract failed: {omittedEmbeddedType}");
if (unrelatedEf.Verdict != ScanVerdict.Clean)
    throw new InvalidOperationException($"Unrelated /EF was treated as FileSpec: {unrelatedEf}");
if (malformedEmbeddedScalar.Verdict != ScanVerdict.NotInspected
    || malformedEmbeddedStream.Verdict != ScanVerdict.NotInspected)
    throw new InvalidOperationException(
        $"Malformed /EmbeddedFiles was accepted: scalar={malformedEmbeddedScalar} stream={malformedEmbeddedStream}");
if (unrelatedFs.Verdict != ScanVerdict.Clean)
    throw new InvalidOperationException($"Unrelated /FS was treated as FileAttachment: {unrelatedFs}");
if (malformedNameTreeKey.Verdict != ScanVerdict.NotInspected
    || outOfOrderNameTree.Verdict != ScanVerdict.NotInspected
    || invalidNameTreeLimits.Verdict != ScanVerdict.NotInspected
    || missingChildLimits.Verdict != ScanVerdict.NotInspected
    || directNameTreeKid.Verdict != ScanVerdict.NotInspected
    || missingIntermediateLimits.Verdict != ScanVerdict.NotInspected)
    throw new InvalidOperationException(
        $"Malformed /EmbeddedFiles name tree was accepted: key={malformedNameTreeKey} order={outOfOrderNameTree} limits={invalidNameTreeLimits} childLimits={missingChildLimits} directKid={directNameTreeKid} intermediateLimits={missingIntermediateLimits}");
if (validIndirectKid.Verdict != ScanVerdict.Clean)
    throw new InvalidOperationException(
        $"Valid indirect /EmbeddedFiles kid was rejected: {validIndirectKid}");
if (rootNamesWithLimits.Verdict != ScanVerdict.NotInspected
    || rootKidsWithLimits.Verdict != ScanVerdict.NotInspected)
    throw new InvalidOperationException(
        $"Root /Limits was accepted: names={rootNamesWithLimits} kids={rootKidsWithLimits}");
if (hexStringKey.Verdict != ScanVerdict.Clean
    || hexStringKeyAndLimits.Verdict != ScanVerdict.Clean
    || mixedLiteralAndHexKeys.Verdict != ScanVerdict.Clean)
    throw new InvalidOperationException(
        $"Valid hexadecimal PDF strings were rejected: root={hexStringKey} child={hexStringKeyAndLimits} mixed={mixedLiteralAndHexKeys}");
if (mixedLiteralAndHexDuplicate.Verdict != ScanVerdict.NotInspected)
    throw new InvalidOperationException(
        $"Byte-equivalent literal/hexadecimal duplicate was accepted: {mixedLiteralAndHexDuplicate}");
if (unrelatedEmbeddedFiles.Verdict != ScanVerdict.Clean)
    throw new InvalidOperationException(
        $"Unrelated /EmbeddedFiles key was treated as the catalog name tree: {unrelatedEmbeddedFiles}");
if (exhaustedOoxml.Verdict != ScanVerdict.NotInspected)
    throw new InvalidOperationException($"OOXML budget exhaustion did not stop traversal: {exhaustedOoxml}");
if (!divergentStructuralPolicyRejected)
    throw new InvalidOperationException("Divergent injected StructuralValidator policy was accepted.");
if (antivirusClean.Verdict != ScanVerdict.Clean || antivirusClean.Reason is not null)
    throw new InvalidOperationException($"Clean antivirus reason was not normalized: {antivirusClean}");
if (realObjectStream.Verdict != ScanVerdict.Rejected)
    throw new InvalidOperationException($"Real object-stream contract failed: {realObjectStream}");
if (beforeMutation.Verdict != ScanVerdict.Rejected || afterMutation.Verdict != ScanVerdict.Rejected)
    throw new InvalidOperationException(
        $"Mutable-options snapshot contract failed: before={beforeMutation} after={afterMutation}");
if (structuralPdfReason is not null || structuralTxtReason is null)
    throw new InvalidOperationException(
        $"StructuralValidator snapshot contract failed: pdf={structuralPdfReason} txt={structuralTxtReason}");
if (!cancellationPropagated)
    throw new InvalidOperationException("Cancellation was not propagated before structural inspection.");

Console.WriteLine("PackageReference smoke passed: verdicts, strict EOF, contextual PDF name trees/FileSpec (including root /Limits rejection and literal/hex string-byte ordering), OOXML budget, coherent policies, immutable options and cancellation.");

sealed class CleanReasonVirus : IVirusScanner
{
    public string Name => "package-smoke-av";

    public Task<(ScanVerdict Verdict, string? Reason)> ScanAsync(Stream content,
        CancellationToken ct) => Task.FromResult<(ScanVerdict, string?)>((ScanVerdict.Clean, "residual"));
}

sealed class CancelAtEofStream(byte[] bytes, CancellationTokenSource cancellation) : Stream
{
    private int position;
    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => bytes.LongLength;
    public override long Position { get => position; set => throw new NotSupportedException(); }

    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default)
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

    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    public override void Flush() { }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}
