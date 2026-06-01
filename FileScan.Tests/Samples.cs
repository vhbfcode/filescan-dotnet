using System.IO.Compression;
using System.Text;

namespace FileScan.Tests;

/// <summary>Entradas de teste geradas em código (PoC benignos) — nenhum arquivo externo / dado real.</summary>
internal static class Samples
{
    private static byte[] A(string s) => Encoding.ASCII.GetBytes(s);

    private static byte[] Concat(params byte[][] parts)
    {
        var result = new byte[parts.Sum(p => p.Length)];
        int o = 0;
        foreach (var p in parts) { Buffer.BlockCopy(p, 0, result, o, p.Length); o += p.Length; }
        return result;
    }

    private static readonly byte[] PngSig = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    private static readonly byte[] Mz = [0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF];

    // --- PDF ---
    public static byte[] CleanPdf() => A(
        "%PDF-1.4\n" +
        "1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n" +
        "2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n" +
        "3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>endobj\n" +
        "trailer<</Root 1 0 R>>\n%%EOF");

    public static byte[] PdfWithJavaScript() => A(
        "%PDF-1.3\n" +
        "1 0 obj<</Type/Catalog/OpenAction<</S/JavaScript/JS (app.alert\\('x'\\))>>>>endobj\n" +
        "trailer<</Root 1 0 R>>\n%%EOF");

    // Subset de fonte "/AAAAAA+..." e SEM script: não pode dar falso-positivo (regressão do bug do "/AA").
    public static byte[] PdfWithFontSubsetOnly() => A(
        "%PDF-1.4\n" +
        "1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n" +
        "2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n" +
        "3 0 obj<</Type/Page/Parent 2 0 R/Resources<</Font<</F1<</BaseFont/AAAAAA+Lato-Bold/Subtype/Type1>>>>>>>>endobj\n" +
        "trailer<</Root 1 0 R>>\n%%EOF");

    public static byte[] PdfWithEmbeddedExe()
    {
        var stub = Concat(Mz, A("  fake PE stub para teste, nao e executavel real  "));
        var head = A($"%PDF-1.5\n1 0 obj<</Type/Catalog>>endobj\n2 0 obj<</Type/EmbeddedFile/Length {stub.Length}>>\nstream\n");
        var tail = A("\nendstream\nendobj\ntrailer<</Root 1 0 R>>\n%%EOF");
        return Concat(head, stub, tail);
    }

    // --- OOXML ---
    public static byte[] DocxWithDde()
    {
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            AddEntry(zip, "[Content_Types].xml",
                "<?xml version=\"1.0\"?><Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">" +
                "<Default Extension=\"xml\" ContentType=\"application/xml\"/></Types>");
            AddEntry(zip, "word/document.xml",
                "<?xml version=\"1.0\"?><w:document xmlns:w=\"x\"><w:body>" +
                "<w:instrText> DDEAUTO cmd.exe \"/c calc.exe\" </w:instrText></w:body></w:document>");
        }
        return ms.ToArray();

        static void AddEntry(ZipArchive zip, string name, string content)
        {
            using var w = new StreamWriter(zip.CreateEntry(name).Open());
            w.Write(content);
        }
    }

    // --- CSV ---
    public static byte[] CsvInjection() => A("Nome,Valor\n=cmd|'/c calc.exe'!A1,a\n@SUM(1)*x,b\n");
    public static byte[] CsvCleanNegatives() => A("Nome,Saldo,Telefone\nJoao,-150.50,+5511987654321\nMaria,-2000,+551130001000\n");

    // --- Imagens ---
    public static byte[] CleanPng() => Concat(PngSig, A("IHDR imagem de teste, sem script aqui"));
    public static byte[] PngWithScript() => Concat(PngSig, A("IHDR <script>alert('x')</script> tail"));
    public static byte[] PngWithPercentTag() => Concat(PngSig, A("IHDR progresso <% 50 %> fim")); // '<%' não pode dar FP em binário

    // --- Executável ---
    public static byte[] ExeBytes() => Concat(Mz, A("  stub para deteccao de tipo  "));
}
