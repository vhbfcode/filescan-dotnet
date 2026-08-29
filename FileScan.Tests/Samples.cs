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

    // PDF com nome hex-codificado: /J#53 → /JS  (evasão de inspetor literal)
    public static byte[] PdfWithHexEncodedJs() => A(
        "%PDF-1.3\n" +
        "1 0 obj<</Type/Catalog/OpenAction<</S/J#53/J#53 (app.alert\\('x'\\))>>>>endobj\n" +
        "trailer<</Root 1 0 R>>\n%%EOF");

    // PDF com /JavaScript parcialmente hex-codificado: /Java#53cript → /JavaScript.
    // SEM /JS auxiliar: só passa se a decodificação casar com o marcador /JavaScript.
    public static byte[] PdfWithPartiallyHexEncodedJavaScript() => A(
        "%PDF-1.3\n" +
        "1 0 obj<</Type/Catalog/OpenAction<</S/Java#53cript (app.alert\\('x'\\))>>>>endobj\n" +
        "trailer<</Root 1 0 R>>\n%%EOF");

    // PDF com /JavaScript totalmente hex-codificado no início: /#4AavaScript → /JavaScript
    // (o 'S' fica literal para casar o marcador case-sensitive). SEM /JS auxiliar.
    public static byte[] PdfWithFullyHexEncodedJavaScript() => A(
        "%PDF-1.3\n" +
        "1 0 obj<</Type/Catalog/OpenAction<</S/#4AavaScript (app.alert\\('x'\\))>>>>endobj\n" +
        "trailer<</Root 1 0 R>>\n%%EOF");

    // PDF com /Launch hex-codificado: /L#61unch
    public static byte[] PdfWithHexEncodedLaunch() => A(
        "%PDF-1.3\n" +
        "1 0 obj<</Type/Catalog/OpenAction<</S/L#61unch/F (calc.exe)>>>>endobj\n" +
        "trailer<</Root 1 0 R>>\n%%EOF");

    // PDF com '#' em bytes binários (fora de nome): não deve gerar falso-positivo
    public static byte[] PdfWithHashInBinaryStream()
    {
        // Dados "binários" com #53 que NÃO estão dentro de um nome PDF
        var binaryData = new byte[] { 0x00, 0xFF, (byte)'#', (byte)'5', (byte)'3', 0xAB, 0xCD };
        var head = A(
            "%PDF-1.4\n" +
            "1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n" +
            "2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n" +
            "3 0 obj<</Type/Page/Parent 2 0 R>>\nstream\n");
        var tail = A("\nendstream\nendobj\ntrailer<</Root 1 0 R>>\n%%EOF");
        return Concat(head, binaryData, tail);
    }

    // Bug real relatado: bytes COMPRIMIDOS (aleatórios) contendo por acaso a sequência "/JS" + delimitador
    // e também "/#4A#53" (que a normalização de nomes sintetizaria em "/JS"). O stream declara
    // /Filter/FlateDecode mas o corpo não é deflate válido — simula o caso em que a descompressão
    // falha e os bytes crus eram julgados. NÃO pode dar falso positivo.
    public static byte[] PdfWithCompressedNoiseLookingLikeJs()
    {
        var noise = Concat(
            [0x1F, 0x8B, 0x42, (byte)'/', (byte)'J', (byte)'S', 0x00, 0x9C, 0xE1],
            [(byte)'/', (byte)'#', (byte)'4', (byte)'A', (byte)'#', (byte)'5', (byte)'3', 0x00, 0x77]);
        var head = A(
            "%PDF-1.4\n" +
            "1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n" +
            $"2 0 obj<</Filter/FlateDecode/Length {noise.Length}>>\nstream\n");
        var tail = A("\nendstream\nendobj\ntrailer<</Root 1 0 R>>\n%%EOF");
        return Concat(head, noise, tail);
    }

    // PDF cujo /JavaScript existe SOMENTE dentro de um stream FlateDecode válido (ex.: object stream):
    // só é detectado se o inspetor descomprimir e varrer o conteúdo inflado.
    public static byte[] PdfWithJavaScriptOnlyInsideFlateStream()
    {
        var payload = A("7 0 obj<</S/JavaScript/JS (app.alert\\('x'\\))>>endobj");
        using var ms = new MemoryStream();
        using (var z = new ZLibStream(ms, CompressionLevel.Optimal, leaveOpen: true))
            z.Write(payload, 0, payload.Length);
        var deflated = ms.ToArray();

        var head = A(
            "%PDF-1.5\n" +
            "1 0 obj<</Type/Catalog>>endobj\n" +
            $"2 0 obj<</Type/ObjStm/Filter/FlateDecode/Length {deflated.Length}>>\nstream\n");
        var tail = A("\nendstream\nendobj\ntrailer<</Root 1 0 R>>\n%%EOF");
        return Concat(head, deflated, tail);
    }

    // Stream SEM /Filter (corpo literal) carregando o marcador: o corpo cru deve continuar varrido.
    public static byte[] PdfWithJavaScriptInUnfilteredStream() => A(
        "%PDF-1.4\n" +
        "1 0 obj<</Type/Catalog>>endobj\n" +
        "2 0 obj<</Type/ObjStm/Length 52>>\nstream\n" +
        "7 0 obj<</S/JavaScript/JS (app.alert\\('x'\\))>>endobj\n" +
        "endstream\nendobj\ntrailer<</Root 1 0 R>>\n%%EOF");

    // "stream" sem "endstream" (truncado/malformado) com o marcador depois: falha para o lado da
    // detecção — o restante do arquivo é varrido cru.
    public static byte[] PdfTruncatedStreamWithJavaScriptAfter() => A(
        "%PDF-1.4\n" +
        "1 0 obj<</Type/Catalog>>endobj\n" +
        "2 0 obj<</Filter/FlateDecode/Length 999>>\nstream\n" +
        "3 0 obj<</S/JavaScript/JS (app.alert\\('x'\\))>>endobj\n%%EOF");

    // PDF com '#' dentro de um nome que NÃO é seguido de dois hex-dígitos: deve ser literal (sem crash)
    public static byte[] PdfWithInvalidHashEscapeInName() => A(
        "%PDF-1.4\n" +
        "1 0 obj<</Type/Catalog/SomeName/Foo#ZZBar>>endobj\n" +
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

    /// <summary>DOCX com uma "imagem" binária embutida cujos bytes contêm "&lt;%" por acaso — não pode dar FP.</summary>
    public static byte[] DocxWithImageContainingPercentBytes()
    {
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            using (var w = new StreamWriter(zip.CreateEntry("word/document.xml").Open()))
                w.Write("<?xml version=\"1.0\"?><w:document xmlns:w=\"x\"><w:body/></w:document>");

            using var s = zip.CreateEntry("word/media/image1.png").Open();
            var img = Concat(PngSig, A("imagem binaria com <% por acaso"));
            s.Write(img, 0, img.Length);
        }
        return ms.ToArray();
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
