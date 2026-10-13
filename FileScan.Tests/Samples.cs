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

    private readonly record struct PdfObject(int Number, byte[] Body);

    /// <summary>
    /// Transformação de TEXTO aplicada a todo corpo de objeto gerado (só na thread corrente): o teste diferencial
    /// reescreve chaves com escapes #xx (/K#69ds) e rebuilds os mesmos ataques.
    /// </summary>
    [ThreadStatic]
    public static Func<string, string>? BodyTransform;

    private static string Tx(string text) => BodyTransform is { } transform ? transform(text) : text;

    private static PdfObject Obj(int number, string body) => new(number, A(Tx(body)));

    private static PdfObject StreamObj(int number, string dictionary, byte[] body) =>
        new(number, Concat(
            A($"<<{dictionary}/Length {body.Length}>>\nstream\n"),
            body,
            A("\nendstream")));

    private static PdfObject RawStreamObj(int number, string dictionary, byte[] body) =>
        new(number, Concat(A($"<<{dictionary}>>\nstream\n"), body, A("\nendstream")));

    /// <summary>
    /// Monta um PDF com xref/trailer/startxref coerentes. As fixtures que pretendem concluir Clean
    /// usam esta fronteira; amostras deliberadamente truncadas/corrompidas continuam cruas.
    /// </summary>
    private static byte[] Pdf(IEnumerable<PdfObject> source, string trailerExtra = "", string betweenObjects = "", int offsetShift = 0, string xrefStyle = "")
    {
        var objects = source.OrderBy(x => x.Number).ToArray();
        int maxObject = objects.Max(x => x.Number);
        var offsets = new Dictionary<int, long>();
        using var output = new MemoryStream();

        Write(A("%PDF-1.7\n%\xE2\xE3\xCF\xD3\n"));
        foreach (var item in objects)
        {
            offsets[item.Number] = output.Position;
            Write(A($"{item.Number} 0 obj\n"));
            Write(item.Body);
            Write(A("\nendobj\n"));
            if (betweenObjects.Length > 0) Write(Encoding.Latin1.GetBytes(betweenObjects));
        }

        long xref = output.Position;
        Write(A(xrefStyle == "headerspace" ? $"xref\n0  {maxObject + 1}\n" : $"xref\n0 {maxObject + 1}\n"));
        Write(A(xrefStyle == "19" ? "0000000000 65535 f\n" : "0000000000 65535 f \n"));
        for (int number = 1; number <= maxObject; number++)
        {
            if (offsets.TryGetValue(number, out long offset))
                Write(A($"{offset - (number > 1 ? offsetShift : 0):0000000000} 00000 n{(xrefStyle == "19" ? "" : " ")}\n"));
            else
                Write(A(xrefStyle == "19" ? "0000000000 65535 f\n" : "0000000000 65535 f \n"));
        }

        Write(A($"trailer\n<</Size {maxObject + 1}/Root 1 0 R{trailerExtra}>>\n"));
        Write(A($"startxref\n{xref}\n%%EOF\n"));
        return output.ToArray();

        void Write(byte[] bytes) => output.Write(bytes, 0, bytes.Length);
    }

    private static byte[] Pdf(params PdfObject[] objects) => Pdf(objects.AsEnumerable());

    private static PdfObject[] MinimalPages(PdfObject? extra = null)
    {
        var objects = new List<PdfObject>
        {
            Obj(1, "<</Type/Catalog/Pages 2 0 R>>"),
            Obj(2, "<</Type/Pages/Kids[3 0 R]/Count 1>>"),
            Obj(3, "<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>"),
        };
        if (extra is { } value) objects.Add(value);
        return objects.ToArray();
    }

    private static readonly byte[] PngSig = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    private static readonly byte[] Mz = [0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF];

    // --- PDF ---
    public static byte[] CleanPdf() => Pdf(MinimalPages());

    public static byte[] PdfWithJavaScript() => Pdf(
        Obj(1, "<</Type/Catalog/Pages 2 0 R/OpenAction<</S/JavaScript/JS(app.alert\\('x'\\))>>>>"),
        Obj(2, "<</Type/Pages/Kids[]/Count 0>>"));

    // Subset de fonte "/AAAAAA+..." e SEM script: não pode dar falso-positivo (regressão do bug do "/AA").
    public static byte[] PdfWithFontSubsetOnly() => Pdf(
        Obj(1, "<</Type/Catalog/Pages 2 0 R>>"),
        Obj(2, "<</Type/Pages/Kids[3 0 R]/Count 1>>"),
        Obj(3, "<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Resources<</Font<</F1<</BaseFont/AAAAAA+Lato-Bold/Subtype/Type1>>>>>>>>"));

    // PDF com nome hex-codificado: /J#53 → /JS  (evasão de inspetor literal)
    public static byte[] PdfWithHexEncodedJs() => Pdf(
        Obj(1, "<</Type/Catalog/Pages 2 0 R/OpenAction<</S/J#53/J#53(app.alert\\('x'\\))>>>>"),
        Obj(2, "<</Type/Pages/Kids[]/Count 0>>"));

    // PDF com /JavaScript parcialmente hex-codificado: /Java#53cript → /JavaScript.
    // SEM /JS auxiliar: só passa se a decodificação casar com o marcador /JavaScript.
    public static byte[] PdfWithPartiallyHexEncodedJavaScript() => Pdf(
        Obj(1, "<</Type/Catalog/Pages 2 0 R/OpenAction<</S/Java#53cript(app.alert\\('x'\\))>>>>"),
        Obj(2, "<</Type/Pages/Kids[]/Count 0>>"));

    // PDF com /JavaScript totalmente hex-codificado no início: /#4AavaScript → /JavaScript
    // (o 'S' fica literal para casar o marcador case-sensitive). SEM /JS auxiliar.
    public static byte[] PdfWithFullyHexEncodedJavaScript() => Pdf(
        Obj(1, "<</Type/Catalog/Pages 2 0 R/OpenAction<</S/#4AavaScript(app.alert\\('x'\\))>>>>"),
        Obj(2, "<</Type/Pages/Kids[]/Count 0>>"));

    // PDF com /Launch hex-codificado: /L#61unch
    public static byte[] PdfWithHexEncodedLaunch() => Pdf(
        Obj(1, "<</Type/Catalog/Pages 2 0 R/OpenAction<</S/L#61unch/F(calc.exe)>>>>"),
        Obj(2, "<</Type/Pages/Kids[]/Count 0>>"));

    // PDF com '#' em bytes binários (fora de nome): não deve gerar falso-positivo
    public static byte[] PdfWithHashInBinaryStream()
    {
        // Dados "binários" com #53 que NÃO estão dentro de um nome PDF
        var binaryData = new byte[] { 0x00, 0xFF, (byte)'#', (byte)'5', (byte)'3', 0xAB, 0xCD };
        return Pdf(MinimalPages(StreamObj(4, string.Empty, binaryData)));
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
        return Pdf(MinimalPages(StreamObj(4, "/Filter/FlateDecode", noise)));
    }

    // PDF cujo /JavaScript existe SOMENTE num stream FlateDecode comum rotulado /ObjStm.
    // Prova a varredura do conteúdo inflado; a fixture estrutural com xref tipo 2 está abaixo.
    public static byte[] PdfWithJavaScriptOnlyInsideFlateStream()
    {
        var payload = A("7 0 obj<</S/JavaScript/JS (app.alert\\('x'\\))>>endobj");
        using var ms = new MemoryStream();
        using (var z = new ZLibStream(ms, CompressionLevel.Optimal, leaveOpen: true))
            z.Write(payload, 0, payload.Length);
        var deflated = ms.ToArray();

        return Pdf(MinimalPages(StreamObj(4, "/Type/ObjStm/N 1/First 4/Filter/FlateDecode", deflated)));
    }

    public static byte[] PdfWithJavaScriptInRealObjectStream()
    {
        byte[] objectStreamBody = A("7 0 <</S/JavaScript/JS(app.alert\\('x'\\))>>");
        byte[] compressedBody = Zlib(objectStreamBody);
        var offsets = new Dictionary<int, long>();
        using var output = new MemoryStream();

        Write(A("%PDF-1.7\n%\xE2\xE3\xCF\xD3\n"));
        WriteObject(1, A("<</Type/Catalog/Pages 2 0 R/OpenAction 7 0 R>>"));
        WriteObject(2, A("<</Type/Pages/Kids[]/Count 0>>"));
        WriteObject(4, Concat(
            A($"<</Type/ObjStm/N 1/First 4/Filter/FlateDecode/Length {compressedBody.Length}>>\nstream\n"),
            compressedBody,
            A("\nendstream")));

        long xrefOffset = output.Position;
        offsets[5] = xrefOffset;
        byte[] xrefEntries = new byte[8 * 7];
        WriteXrefEntry(xrefEntries, 0, 0, 0, 65535);
        WriteXrefEntry(xrefEntries, 1, 1, offsets[1], 0);
        WriteXrefEntry(xrefEntries, 2, 1, offsets[2], 0);
        WriteXrefEntry(xrefEntries, 3, 0, 0, 0);
        WriteXrefEntry(xrefEntries, 4, 1, offsets[4], 0);
        WriteXrefEntry(xrefEntries, 5, 1, offsets[5], 0);
        WriteXrefEntry(xrefEntries, 6, 0, 0, 0);
        WriteXrefEntry(xrefEntries, 7, 2, 4, 0);

        Write(A("5 0 obj\n"));
        Write(A($"<</Type/XRef/Size 8/Root 1 0 R/W[1 4 2]/Index[0 8]/Length {xrefEntries.Length}>>\nstream\n"));
        Write(xrefEntries);
        Write(A($"\nendstream\nendobj\nstartxref\n{xrefOffset}\n%%EOF\n"));
        return output.ToArray();

        void Write(byte[] bytes) => output.Write(bytes, 0, bytes.Length);

        void WriteObject(int number, byte[] body)
        {
            offsets[number] = output.Position;
            Write(A($"{number} 0 obj\n"));
            Write(body);
            Write(A("\nendobj\n"));
        }

        static void WriteXrefEntry(byte[] target, int index, byte type, long field1, int field2)
        {
            int offset = index * 7;
            target[offset] = type;
            target[offset + 1] = (byte)(field1 >> 24);
            target[offset + 2] = (byte)(field1 >> 16);
            target[offset + 3] = (byte)(field1 >> 8);
            target[offset + 4] = (byte)field1;
            target[offset + 5] = (byte)(field2 >> 8);
            target[offset + 6] = (byte)field2;
        }
    }

    // Stream SEM /Filter (corpo literal) carregando o marcador: o corpo cru deve continuar varrido.
    public static byte[] PdfWithJavaScriptInUnfilteredStream() => Pdf(MinimalPages(
        StreamObj(4, "/Type/ObjStm/N 1/First 4",
            A("7 0 <</S/JavaScript/JS(app.alert\\('x'\\))>>"))));

    // "stream" sem "endstream" (truncado/malformado) com o marcador depois: falha para o lado da
    // detecção — o restante do arquivo é varrido cru.
    public static byte[] PdfTruncatedStreamWithJavaScriptAfter() => A(
        "%PDF-1.4\n" +
        "1 0 obj<</Type/Catalog>>endobj\n" +
        "2 0 obj<</Filter/FlateDecode/Length 999>>\nstream\n" +
        "3 0 obj<</S/JavaScript/JS (app.alert\\('x'\\))>>endobj\n%%EOF");

    // PDF com '#' dentro de um nome que NÃO é seguido de dois hex-dígitos: deve ser literal (sem crash)
    public static byte[] PdfWithInvalidHashEscapeInName() => Pdf(
        Obj(1, "<</Type/Catalog/Pages 2 0 R/SomeName/Foo#ZZBar>>"),
        Obj(2, "<</Type/Pages/Kids[]/Count 0>>"));

    public static byte[] PdfWithEmbeddedExe()
    {
        var stub = Concat(Mz, A("  fake PE stub para teste, nao e executavel real  "));
        return Pdf(MinimalPages(StreamObj(4, "/Type/EmbeddedFile", stub)));
    }

    // Frente C: /EmbeddedFile com escape #XX de nome (/Embedded#46ile, #46 = 'F') — o extrator
    // precisa da MESMA normalização do inspetor de ações, senão o anexo evade a inspeção recursiva.
    public static byte[] PdfWithHexEscapedEmbeddedFileExe()
    {
        var stub = Concat(Mz, A("  fake PE stub para teste, nao e executavel real  "));
        return Pdf(MinimalPages(StreamObj(4, "/Type/Embedded#46ile", stub)));
    }

    public static byte[] PdfWithFileSpecEfExecutable(bool declareStreamType = false,
        bool declareFileSpecType = true, bool compressed = false)
    {
        var stub = Concat(Mz, A("  harmless synthetic PE-shaped fixture  "));
        string filespecType = declareFileSpecType ? "/Type/Filespec" : string.Empty;
        string streamType = declareStreamType ? "/Type/EmbeddedFile" : string.Empty;
        byte[] body = compressed ? Zlib(stub) : stub;
        string filter = compressed ? "/Filter/FlateDecode" : string.Empty;
        return Pdf(
            Obj(1, "<</Type/Catalog/Pages 2 0 R/Names<</EmbeddedFiles<</Names[(payload.exe) 3 0 R]>>>>>>"),
            Obj(2, "<</Type/Pages/Kids[]/Count 0>>"),
            Obj(3, $"<<{filespecType}/F(payload.exe)/EF<</F 4 0 R>>>>"),
            StreamObj(4, $"{streamType}{filter}", body));
    }

    public static byte[] PdfWithFileSpecEfMissingReference() => Pdf(
        Obj(1, "<</Type/Catalog/Pages 2 0 R/Names<</EmbeddedFiles<</Names[(payload.exe) 3 0 R]>>>>>>"),
        Obj(2, "<</Type/Pages/Kids[]/Count 0>>"),
        Obj(3, "<</Type/Filespec/F(payload.exe)/EF<</F 99 0 R>>>>"));

    public static byte[] PdfWithFileSpecEfNonStream() => Pdf(
        Obj(1, "<</Type/Catalog/Pages 2 0 R/Names<</EmbeddedFiles<</Names[(payload.exe) 3 0 R]>>>>>>"),
        Obj(2, "<</Type/Pages/Kids[]/Count 0>>"),
        Obj(3, "<</Type/Filespec/F(payload.exe)/EF<</F 4 0 R>>>>"),
        Obj(4, "<</NotAStream true>>"));

    public static byte[] PdfWithIndirectEfDictionaryExecutable() => Pdf(
        Obj(1, "<</Type/Catalog/Pages 2 0 R/Names<</EmbeddedFiles<</Names[(payload.exe) 3 0 R]>>>>>>"),
        Obj(2, "<</Type/Pages/Kids[]/Count 0>>"),
        Obj(3, "<</F(payload.exe)/EF 5 0 R>>"),
        StreamObj(4, string.Empty,
            Concat(Mz, A("  harmless synthetic PE-shaped fixture  "))),
        Obj(5, "<</UF 4 0 R>>"));

    public static byte[] PdfWithCyclicEfReference() => Pdf(
        Obj(1, "<</Type/Catalog/Pages 2 0 R/Names<</EmbeddedFiles<</Names[(payload.exe) 3 0 R]>>>>>>"),
        Obj(2, "<</Type/Pages/Kids[]/Count 0>>"),
        Obj(3, "<</Type/Filespec/F(payload.exe)/EF 5 0 R>>"),
        Obj(5, "5 0 R"));

    public static byte[] PdfWithUnrelatedCatalogEfKey(bool scalar = false)
    {
        if (scalar)
            return Pdf(
                Obj(1, "<</Type/Catalog/Pages 2 0 R/EF 42>>"),
                Obj(2, "<</Type/Pages/Kids[]/Count 0>>"));

        return Pdf(
            Obj(1, "<</Type/Catalog/Pages 2 0 R/EF<</F 3 0 R>>>>"),
            Obj(2, "<</Type/Pages/Kids[]/Count 0>>"),
            StreamObj(3, string.Empty,
                Concat(Mz, A("  unrelated extension payload  "))));
    }

    public static byte[] PdfWithEmbeddedFilesScalarValue() => Pdf(
        Obj(1, "<</Type/Catalog/Pages 2 0 R/Names<</EmbeddedFiles<</Names[(payload.exe) 42]>>>>>>"),
        Obj(2, "<</Type/Pages/Kids[]/Count 0>>"));

    public static byte[] PdfWithEmbeddedFilesDirectStream() => Pdf(
        Obj(1, "<</Type/Catalog/Pages 2 0 R/Names<</EmbeddedFiles<</Names[(payload.exe) 4 0 R]>>>>>>"),
        Obj(2, "<</Type/Pages/Kids[]/Count 0>>"),
        StreamObj(4, string.Empty,
            Concat(Mz, A("  direct stream is not a FileSpec  "))));

    public static byte[] PdfWithEmbeddedFilesExternalPathString() => Pdf(
        Obj(1, "<</Type/Catalog/Pages 2 0 R/Names<</EmbeddedFiles<</Names[(manual.txt)(relative/manual.txt)]>>>>>>"),
        Obj(2, "<</Type/Pages/Kids[]/Count 0>>"));

    public static byte[] PdfWithEmbeddedFilesNonStringKey() => Pdf(
        Obj(1, "<</Type/Catalog/Pages 2 0 R/Names<</EmbeddedFiles<</Names[42(relative/manual.txt)]>>>>>>"),
        Obj(2, "<</Type/Pages/Kids[]/Count 0>>"));

    public static byte[] PdfWithEmbeddedFilesOutOfOrderKeys() => Pdf(
        Obj(1, "<</Type/Catalog/Pages 2 0 R/Names<</EmbeddedFiles<</Names[(z)(z.txt)(a)(a.txt)]>>>>>>"),
        Obj(2, "<</Type/Pages/Kids[]/Count 0>>"));

    public static byte[] PdfWithEmbeddedFilesInvalidLimits() => Pdf(
        Obj(1, "<</Type/Catalog/Pages 2 0 R/Names<</EmbeddedFiles<</Names[(a)(a.txt)]/Limits[(b)(b)]>>>>>>"),
        Obj(2, "<</Type/Pages/Kids[]/Count 0>>"));

    public static byte[] PdfWithEmbeddedFilesRootNamesAndLimits() => Pdf(
        Obj(1, "<</Type/Catalog/Pages 2 0 R/Names<</EmbeddedFiles<</Names[(a)(a.txt)]/Limits[(a)(a)]>>>>>>"),
        Obj(2, "<</Type/Pages/Kids[]/Count 0>>"));

    public static byte[] PdfWithEmbeddedFilesRootKidsAndLimits() => Pdf(
        Obj(1, "<</Type/Catalog/Pages 2 0 R/Names<</EmbeddedFiles 3 0 R>>>>"),
        Obj(2, "<</Type/Pages/Kids[]/Count 0>>"),
        Obj(3, "<</Kids[4 0 R]/Limits[(a)(a)]>>"),
        Obj(4, "<</Names[(a)(a.txt)]/Limits[(a)(a)]>>"));

    public static byte[] PdfWithEmbeddedFilesHexStringKey() => Pdf(
        Obj(1, "<</Type/Catalog/Pages 2 0 R/Names<</EmbeddedFiles<</Names[<61>(a.txt)]>>>>>>"),
        Obj(2, "<</Type/Pages/Kids[]/Count 0>>"));

    public static byte[] PdfWithEmbeddedFilesHexStringKeyAndLimits() => Pdf(
        Obj(1, "<</Type/Catalog/Pages 2 0 R/Names<</EmbeddedFiles 3 0 R>>>>"),
        Obj(2, "<</Type/Pages/Kids[]/Count 0>>"),
        Obj(3, "<</Kids[4 0 R]>>"),
        Obj(4, "<</Names[<61>(a.txt)]/Limits[<61><61>]>>"));

    public static byte[] PdfWithEmbeddedFilesMixedLiteralAndHexKeys() => Pdf(
        Obj(1, "<</Type/Catalog/Pages 2 0 R/Names<</EmbeddedFiles<</Names[(a)(a.txt)<62>(b.txt)]>>>>>>"),
        Obj(2, "<</Type/Pages/Kids[]/Count 0>>"));

    public static byte[] PdfWithEmbeddedFilesMixedDuplicateKeys() => Pdf(
        Obj(1, "<</Type/Catalog/Pages 2 0 R/Names<</EmbeddedFiles<</Names[(a)(a.txt)<61>(duplicate.txt)]>>>>>>"),
        Obj(2, "<</Type/Pages/Kids[]/Count 0>>"));

    public static byte[] PdfWithEmbeddedFilesChildMissingLimits() => Pdf(
        Obj(1, "<</Type/Catalog/Pages 2 0 R/Names<</EmbeddedFiles 3 0 R>>>>"),
        Obj(2, "<</Type/Pages/Kids[]/Count 0>>"),
        Obj(3, "<</Kids[4 0 R]>>"),
        Obj(4, "<</Names[(a)(a.txt)]>>"));

    public static byte[] PdfWithEmbeddedFilesDirectKid() => Pdf(
        Obj(1, "<</Type/Catalog/Pages 2 0 R/Names<</EmbeddedFiles<</Kids[<</Names[(a)(a.txt)]/Limits[(a)(a)]>>]>>>>>>"),
        Obj(2, "<</Type/Pages/Kids[]/Count 0>>"));

    public static byte[] PdfWithEmbeddedFilesIntermediateNodeMissingLimits() => Pdf(
        Obj(1, "<</Type/Catalog/Pages 2 0 R/Names<</EmbeddedFiles 3 0 R>>>>"),
        Obj(2, "<</Type/Pages/Kids[]/Count 0>>"),
        Obj(3, "<</Kids[4 0 R]>>"),
        Obj(4, "<</Kids[5 0 R]>>"),
        Obj(5, "<</Names[(a)(a.txt)]/Limits[(a)(a)]>>"));

    public static byte[] PdfWithEmbeddedFilesValidIndirectKid() => Pdf(
        Obj(1, "<</Type/Catalog/Pages 2 0 R/Names<</EmbeddedFiles 3 0 R>>>>"),
        Obj(2, "<</Type/Pages/Kids[]/Count 0>>"),
        Obj(3, "<</Kids[4 0 R]>>"),
        Obj(4, "<</Names[(a)(a.txt)]/Limits[(a)(a)]>>"));

    public static byte[] PdfWithUnrelatedEmbeddedFilesKey() => Pdf(
        Obj(1, "<</Type/Catalog/Pages 2 0 R/Acme<</EmbeddedFiles 42>>>>"),
        Obj(2, "<</Type/Pages/Kids[]/Count 0>>"));

    public static byte[] PdfWithUnrelatedCustomFsKey() => Pdf(
        Obj(1, "<</Type/Catalog/Pages 2 0 R/Acme<</FS 3 0 R>>>>"),
        Obj(2, "<</Type/Pages/Kids[]/Count 0>>"),
        Obj(3, "<</F(payload.exe)/EF<</F 4 0 R>>>>"),
        StreamObj(4, string.Empty,
            Concat(Mz, A("  unrelated custom dictionary payload  "))));

    public static byte[] PdfWithAssociatedFileExecutable() => Pdf(
        Obj(1, "<</Type/Catalog/Pages 2 0 R/AF[3 0 R]>>"),
        Obj(2, "<</Type/Pages/Kids[]/Count 0>>"),
        Obj(3, "<</F(payload.exe)/EF<</F 4 0 R>>>>"),
        StreamObj(4, string.Empty,
            Concat(Mz, A("  associated file payload  "))));

    public static byte[] PdfWithFileAttachmentExecutable() => Pdf(
        Obj(1, "<</Type/Catalog/Pages 2 0 R>>"),
        Obj(2, "<</Type/Pages/Kids[]/Count 0>>"),
        Obj(3, "<</Subtype/FileAttachment/FS 4 0 R>>"),
        Obj(4, "<</F(payload.exe)/EF<</F 5 0 R>>>>"),
        StreamObj(5, string.Empty,
            Concat(Mz, A("  file attachment payload  "))));

    // --- Frente B1: marcadores em contexto INERTE (string, comentário, texto de página) ---
    // Nenhum destes pode rejeitar: para um leitor de PDF, nada aqui é ação.

    public static byte[] PdfWithMarkerOnlyInLiteralString() =>
        Pdf(MinimalPages(Obj(4, "<</Title(manual sobre /JavaScript, /JS e /Launch em PDF)>>")));

    public static byte[] PdfWithMarkerOnlyInComment() => Pdf(
        Obj(1, "% nota interna: /JavaScript /Launch\n<</Type/Catalog/Pages 2 0 R>>"),
        Obj(2, "<</Type/Pages/Kids[]/Count 0>>"));

    // Texto de página (dentro de literal string) num content stream NÃO comprimido.
    public static byte[] PdfWithMarkerInPageTextUncompressed()
    {
        var body = A("BT /F1 12 Tf (aula sobre /JS e /Launch em PDF) Tj ET");
        return Pdf(
            Obj(1, "<</Type/Catalog/Pages 2 0 R>>"),
            Obj(2, "<</Type/Pages/Kids[3 0 R]/Count 1>>"),
            Obj(3, "<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 4 0 R>>"),
            StreamObj(4, string.Empty, body));
    }

    // O MESMO texto de página, agora em Flate: infla, varre o texto — e o marcador segue em string.
    public static byte[] PdfWithMarkerInPageTextFlate()
    {
        var deflated = Zlib(A("BT /F1 12 Tf (aula sobre /JS e /Launch em PDF) Tj ET"));
        return Pdf(
            Obj(1, "<</Type/Catalog/Pages 2 0 R>>"),
            Obj(2, "<</Type/Pages/Kids[3 0 R]/Count 1>>"),
            Obj(3, "<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 4 0 R>>"),
            StreamObj(4, "/Filter/FlateDecode", deflated));
    }

    // "caso 11" GENUINAMENTE benigno: bytes "endstream" DENTRO do corpo delimitado por /Length
    // válido (blocos zlib armazenados preservam o texto cru). Só o parse de /Length mantém a
    // segmentação alinhada. Dente da sabotagem: o "endstream" embutido está DENTRO de uma literal
    // string que também contém "/JS" — cortar o corpo textualmente deixa o "/JS" fora da string
    // (FP) ou torna o zlib ilegível (incompleto); os dois desfechos derrubam o teste.
    public static byte[] PdfWithEndstreamBytesInsideMeasuredStream()
    {
        var deflated = Zlib(A("abc (aqui endstream segue /JS dentro da string) fim"), CompressionLevel.NoCompression);
        return Pdf(
            Obj(1, "<</Type/Catalog/Pages 2 0 R>>"),
            Obj(2, "<</Type/Pages/Kids[3 0 R]/Count 1>>"),
            Obj(3, "<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 4 0 R>>"),
            StreamObj(4, "/Filter/FlateDecode", deflated));
    }

    // Evasão simétrica: /Length MENTIROSO (menor que o corpo real) escondendo um dicionário com
    // JavaScript no "vão" entre o fim declarado e o endstream — o vão é estrutural e é varrido.
    public static byte[] PdfHidingJsAfterDeclaredLength() => A(
        "%PDF-1.4\n" +
        "1 0 obj<</Type/Catalog>>endobj\n" +
        "2 0 obj<</Length 4>>\nstream\n" +
        "AAAA<</S/JavaScript/JS (x)>>\n" +
        "endstream\nendobj\ntrailer<</Root 1 0 R>>\n%%EOF");

    // --- Frente B2: corpo NÃO inspecionável nunca vira Clean ---

    // /Filter não suportado (LZWDecode) com um /JS cru escondido no corpo: não pode ser julgado
    // cru (seria FP noutros casos) nem ignorado em silêncio (fail-open) — vira inspeção incompleta.
    public static byte[] PdfWithLzwFilteredStreamHidingJs()
    {
        var body = Concat([0xFF], A("LZW opaco /JS escondido aqui"));
        return Pdf(MinimalPages(StreamObj(4, "/Filter/LZWDecode", body)));
    }

    // PDF criptografado (trailer com /Encrypt), sem marcador visível: conteúdo cifrado não é
    // inspecionável — nunca Clean.
    public static byte[] PdfEncrypted() => Pdf(
        [
            Obj(1, "<</Type/Catalog/Pages 2 0 R>>"),
            Obj(2, "<</Type/Pages/Kids[]/Count 0>>"),
            Obj(5, "<</Filter/Standard/V 2/R 3/Length 128/P -3904/O<AABBCCDD>/U<EEFF0011>>>"),
        ],
        "/Encrypt 5 0 R/ID[<00112233445566778899AABBCCDDEEFF><00112233445566778899AABBCCDDEEFF>]");

    // PDF estruturalmente truncado (sem %%EOF): inspeção não conclusiva.
    public static byte[] PdfTruncatedNoEof() => A(
        "%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endob");

    // F2: update incremental TRUNCADO — existe um %%EOF intermediário (da revisão anterior), mas
    // a cauda (o update seguinte, >1 KB) foi cortada sem %%EOF final. Só a checagem na CAUDA do
    // buffer detecta; sabotar de volta para IndexOf global derruba o teste.
    public static byte[] PdfTruncatedAfterIntermediateEof()
    {
        var head = A(
            "%PDF-1.4\n" +
            "1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n" +
            "2 0 obj<</Type/Pages/Kids[]/Count 0>>endobj\n" +
            "trailer<</Root 1 0 R>>\n%%EOF\n");
        var truncatedUpdate = A("3 0 obj<</Type/Page/Parent 2 0 R/Annots [" + new string('A', 2000));
        return Concat(head, truncatedUpdate);
    }

    // F1 (pin de contrato): OLE2 sintético sem nenhum marcador visível. A varredura de OLE2 é
    // best-effort e não alimenta Incomplete por construção — o escopo está documentado em
    // ScanVerdict.Clean / READMEs / SECURITY.md.
    public static byte[] Ole2WithoutVisibleMarkers() => Concat(
        [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1],
        A("conteudo binario legado sem macros visiveis"));

    // Stream Flate cujo conteúdo descomprimido tem <paramref name="decompressedSize"/> bytes —
    // usado para provar que estourar o cap de descompressão NÃO passa como Clean.
    public static byte[] PdfWithLargeFlateStream(int decompressedSize)
    {
        var deflated = Zlib(new byte[decompressedSize]); // zeros comprimem para quase nada
        return Pdf(MinimalPages(StreamObj(4, "/Filter/FlateDecode", deflated)));
    }

    public static byte[] PdfWithDictionaryStringContainingObjAndCompressedJs()
    {
        var payload = Zlib(A("<</S/JavaScript/JS(app.alert('x'))>>"));
        return Pdf(MinimalPages(StreamObj(4,
            "/Filter/FlateDecode/Title(obj dentro de string)", payload)));
    }

    public static byte[] PdfWithLiteralStreamKeywordBeforeCompressedJs()
    {
        var payload = Zlib(A("<</S/JavaScript/JS(app.alert('x'))>>"));
        return Pdf(
            Obj(1, "<</Type/Catalog/Pages 2 0 R/Title(stream\\n dentro de literal)>>"),
            Obj(2, "<</Type/Pages/Kids[3 0 R]/Count 1>>"),
            Obj(3, "<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>"),
            StreamObj(4, "/Filter/FlateDecode", payload));
    }

    public static byte[] PdfWithIndirectLengthStream()
    {
        var body = A("BT (texto benigno) Tj ET");
        return Pdf(
            Obj(1, "<</Type/Catalog/Pages 2 0 R>>"),
            Obj(2, "<</Type/Pages/Kids[3 0 R]/Count 1>>"),
            Obj(3, "<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 4 0 R>>"),
            RawStreamObj(4, "/Length 5 0 R", body),
            Obj(5, body.Length.ToString()));
    }

    public static byte[] PdfWithShortTruncatedIncrementalUpdate() =>
        Concat(CleanPdf(), A("4 0 obj<</Type/Page"));

    public static byte[] PdfWithBytesAfterFinalEof() =>
        Concat(CleanPdf(), A("nao-e-whitespace"));

    public static byte[] PdfWithBinaryBytesAfterFinalEof() =>
        Concat(CleanPdf(), [0x50, 0x4B, 0x03, 0x04, 0x00, 0x01]);

    public static byte[] PdfWithUnterminatedLiteralContainingOnlyEof() => A(
        "%PDF-1.7\n1 0 obj<</Type/Catalog/Title(isto não termina %%EOF");

    public static byte[] PdfWithUnterminatedHexString() => A(
        "%PDF-1.7\n1 0 obj<</Type/Catalog/Title<ABCD>>endobj\n%%EOF");

    public static byte[] PdfWithUnknownPredictor()
    {
        var payload = Zlib(A("dados"));
        return Pdf(MinimalPages(StreamObj(4,
            "/Filter/FlateDecode/DecodeParms<</Predictor 12/Columns 1>>", payload)));
    }

    public static byte[] PdfWithManySmallFlateStreams(int count, int expandedBytesPerStream)
    {
        var objects = MinimalPages().ToList();
        for (int index = 0; index < count; index++)
            objects.Add(StreamObj(4 + index, "/Filter/FlateDecode",
                Zlib(new byte[expandedBytesPerStream])));
        return Pdf(objects);
    }

    public static byte[] PdfWithExecutableIn51stEmbeddedFile()
    {
        var objects = MinimalPages().ToList();
        for (int index = 0; index < 50; index++)
            objects.Add(StreamObj(4 + index, "/Type/EmbeddedFile", A($"benigno-{index}")));
        objects.Add(StreamObj(54, "/Type/EmbeddedFile", ExeBytes()));
        return Pdf(objects);
    }

    public static byte[] PdfWithEmbeddedPdfContainingExe()
    {
        byte[] inner = PdfWithEmbeddedExe();
        byte[] middle = Pdf(MinimalPages(StreamObj(4,
            "/Type/EmbeddedFile/Filter/FlateDecode", Zlib(inner))));
        return Pdf(MinimalPages(StreamObj(4,
            "/Type/EmbeddedFile/Filter/FlateDecode", Zlib(middle))));
    }

    public static byte[] PdfWithEmbeddedDepth(int nestedLevels)
    {
        byte[] current = CleanPdf();
        for (int level = 0; level < nestedLevels; level++)
            current = Pdf(MinimalPages(StreamObj(4,
                "/Type/EmbeddedFile/Filter/FlateDecode", Zlib(current))));
        return current;
    }

    private static byte[] Zlib(byte[] payload, CompressionLevel level = CompressionLevel.Optimal)
    {
        using var ms = new MemoryStream();
        using (var z = new ZLibStream(ms, level, leaveOpen: true))
            z.Write(payload, 0, payload.Length);
        return ms.ToArray();
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

    public static byte[] DocxWithOversizedEntryBeforeDde(int oversizedBytes)
    {
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            using (var oversized = zip.CreateEntry("word/oversized.bin").Open())
                oversized.Write(new byte[oversizedBytes]);

            using var writer = new StreamWriter(zip.CreateEntry("word/document.xml").Open());
            writer.Write("<w:instrText>DDEAUTO cmd.exe</w:instrText>");
        }
        return ms.ToArray();
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

    // --- 0.3.0: filtros encadeados, cauda após %%EOF, limite de objetos, papel binário ---
    // Tudo sintético, gerado em código: nenhum PDF real entra no repositório.

    private static byte[] Ascii85(byte[] data)
    {
        var sb = new StringBuilder();
        for (int i = 0; i < data.Length; i += 4)
        {
            int n = Math.Min(4, data.Length - i);
            uint value = 0;
            for (int k = 0; k < 4; k++) value = (value << 8) | (k < n ? data[i + k] : (byte)0);
            if (value == 0 && n == 4) { sb.Append('z'); continue; }

            var chars = new char[5];
            for (int k = 4; k >= 0; k--) { chars[k] = (char)(value % 85 + 33); value /= 85; }
            sb.Append(chars, 0, n + 1);
        }
        sb.Append("~>");
        return Encoding.ASCII.GetBytes(sb.ToString());
    }

    private static byte[] AsciiHex(byte[] data) => A(Convert.ToHexString(data) + ">");

    /// <summary>Stream cujo corpo é <paramref name="body"/> passado por Flate e depois ASCII85 (chain decodifica A85 -> Flate).</summary>
    public static byte[] PdfWithChainedStream(string filters, byte[] body, string extraDictionary = "")
    {
        byte[] encoded = filters switch
        {
            "[/ASCII85Decode/FlateDecode]" => Ascii85(Zlib(body)),
            "[/ASCIIHexDecode/FlateDecode]" => AsciiHex(Zlib(body)),
            "[/ASCII85Decode]" => Ascii85(body),
            _ => throw new ArgumentOutOfRangeException(nameof(filters)),
        };
        return Pdf(MinimalPages(StreamObj(4, $"/Filter{filters}{extraDictionary}", encoded)));
    }

    public static byte[] PdfWithChainedStreamHidingJavaScript() => PdfWithChainedStream(
        "[/ASCII85Decode/FlateDecode]", A("<</S/JavaScript/JS(app.alert\\('x'\\))>>"));

    public static byte[] PdfWithEmbeddedExeInChain()
    {
        byte[] encoded = Ascii85(Zlib(ExeBytes()));
        return Pdf(MinimalPages(StreamObj(4,
            "/Type/EmbeddedFile/Filter[/ASCII85Decode/FlateDecode]", encoded)));
    }

    public static byte[] PdfWithFiveFilterChain() => Pdf(MinimalPages(StreamObj(4,
        "/Filter[/ASCIIHexDecode/ASCIIHexDecode/ASCIIHexDecode/ASCIIHexDecode/ASCIIHexDecode]",
        A("3333333333333333>"))));

    public static byte[] PdfWithLzwInChain() => Pdf(MinimalPages(StreamObj(4,
        "/Filter[/ASCIIHexDecode/LZWDecode]", AsciiHex(A("dados")))));

    public static byte[] PdfWithInvalidAscii85() => Pdf(MinimalPages(StreamObj(4,
        "/Filter[/ASCII85Decode/FlateDecode]", A("!!!!!~~~>>>> isto nao e ascii85 valido {{{ ~>"))));

    public static byte[] PdfWithAscii85ZBomb(int zChars) => Pdf(MinimalPages(StreamObj(4,
        "/Filter[/ASCII85Decode]", Concat(A(new string('z', zChars)), A("~>")))));

    /// <summary>Vários streams ASCII85 pequenos: cada um cabe no teto por stream, a soma não cabe no agregado.</summary>
    public static byte[] PdfWithManyAscii85Streams(int count, int decodedBytesPerStream)
    {
        var objects = MinimalPages().ToList();
        for (int index = 0; index < count; index++)
            objects.Add(StreamObj(4 + index, "/Filter[/ASCII85Decode]",
                Ascii85(Enumerable.Range(0, decodedBytesPerStream).Select(x => (byte)(65 + x % 20)).ToArray())));
        return Pdf(objects);
    }

    public static byte[] PdfWithChainedStreamAndParms(string decodeParms)
    {
        byte[] encoded = Ascii85(Zlib(A("dados benignos")));
        return Pdf(MinimalPages(StreamObj(4,
            $"/Filter[/ASCII85Decode/FlateDecode]/DecodeParms{decodeParms}", encoded)));
    }

    /// <summary>Cauda arbitrária colada depois do %%EOF final de um PDF íntegro.</summary>
    public static byte[] PdfWithTail(byte[] tail) => Concat(CleanPdf(), tail);

    /// <summary>PDF íntegro + atualização incremental BEM formada (2º xref com /Prev, startxref e %%EOF) + cauda opcional.</summary>
    public static byte[] PdfWithIncrementalUpdate(string objectBody, byte[]? tail = null)
    {
        byte[] original = CleanPdf();
        string text = Encoding.ASCII.GetString(original);
        int start = text.LastIndexOf("startxref\n", StringComparison.Ordinal) + "startxref\n".Length;
        string previous = text[start..text.IndexOf('\n', start)];

        byte[] update = A($"4 0 obj\n{objectBody}\nendobj\n");
        long xrefOffset = original.Length + update.Length;
        long objectOffset = original.Length;
        byte[] section = A(
            "xref\n0 1\n0000000000 65535 f \n4 1\n" + $"{objectOffset:0000000000} 00000 n \n" +
            $"trailer\n<</Size 5/Root 1 0 R/Prev {previous}>>\nstartxref\n{xrefOffset}\n%%EOF\n");
        return Concat(original, update, section, tail ?? []);
    }

    /// <summary>CleanPdf com o trecho final "startxref\nN\n%%EOF\n" trocado por <paramref name="shape"/>(N).</summary>
    public static byte[] PdfWithEofShape(Func<string, string> shape)
    {
        string text = Encoding.Latin1.GetString(CleanPdf());
        int keyword = text.LastIndexOf("startxref", StringComparison.Ordinal);
        string offset = text[(keyword + "startxref\n".Length)..text.IndexOf('\n', keyword + "startxref\n".Length)];
        return Encoding.Latin1.GetBytes(text[..keyword] + shape(offset));
    }

    /// <summary>startxref sem offset numérico antes do %%EOF.</summary>
    public static byte[] PdfWithNoStartxrefOffset() => A(
        "%PDF-1.7\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n2 0 obj<</Type/Pages/Kids[]/Count 0>>endobj\n" +
        "trailer<</Root 1 0 R>>\nstartxref\n%%EOF\n");

    public static byte[] PdfWithEfOutsideFilespec(bool dct) => Pdf(MinimalPages().Concat(
    [
        Obj(4, "<</S/GoToE/EF<</F 5 0 R>>>>"),
        dct
            ? StreamObj(5, "/Subtype/Image/Filter/DCTDecode", ExeBytes())
            : StreamObj(5, "/Filter/FlateDecode", Zlib(ExeBytes())),
    ]));

    public static byte[] PdfWithMalformedEf() => Pdf(MinimalPages().Concat(
    [
        Obj(4, "<</S/GoToE/EF 7>>"),
    ]));


    public static byte[] PdfWithManyObjects(int totalObjects)
    {
        var objects = MinimalPages().ToList();
        for (int number = 4; number <= totalObjects; number++)
            objects.Add(Obj(number, "<</Tipo/Teste>>"));
        return Pdf(objects);
    }

    // Bytes "binários" de fonte: '(' e '<' soltos que o léxico PDF leria como string aberta.
    private static byte[] FontLikeBinary(string prefix = "") =>
        Concat(A(prefix), [0x00, 0x01, 0x00, 0x00, 0x28, 0x13, 0x3C, 0xA7, 0x28, 0x03, 0x3C, 0x00]);

    public static byte[] PdfWithFontFile2(byte[] fontProgram) => Pdf(MinimalPages().Concat(
    [
        Obj(4, "<</Type/FontDescriptor/FontName/Teste/Flags 4/FontFile2 5 0 R>>"),
        StreamObj(5, "/Length1 12", fontProgram),
    ]));

    public static byte[] PdfWithFontFile2Binary() => PdfWithFontFile2(FontLikeBinary());

    public static byte[] PdfWithFontFile2HidingJavaScript() =>
        PdfWithFontFile2(FontLikeBinary("/JavaScript "));

    public static byte[] PdfWithUnreferencedBinaryStream() => Pdf(MinimalPages(
        StreamObj(4, "/Length1 12", FontLikeBinary())));

    public static byte[] PdfWithIccProfileBinary() => Pdf(MinimalPages().Concat(
    [
        Obj(4, "<</Type/Page/Parent 2 0 R/Resources<</ColorSpace<</Cs1[/ICCBased 5 0 R]>>>>>>"),
        StreamObj(5, "/N 3", FontLikeBinary()),
    ]));

    public static byte[] PdfWithObjStmReferencedAsFontFile() => Pdf(MinimalPages().Concat(
    [
        Obj(4, "<</Type/FontDescriptor/FontName/Teste/Flags 4/FontFile2 5 0 R>>"),
        StreamObj(5, "/Type/ObjStm/N 0/First 0", A("(isto nao termina")),
    ]));

    public static byte[] PdfWithJpegImage() => Pdf(MinimalPages(StreamObj(4,
        "/Type/XObject/Subtype/Image/Width 1/Height 1/ColorSpace/DeviceGray/BitsPerComponent 8/Filter/DCTDecode",
        [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0xFF, 0xD9])));

    /// <summary>Imagem raster em Flate, grande o bastante para estourar o teto por stream se fosse decodificada.</summary>
    public static byte[] PdfWithLargeFlateImage(int decodedBytes) => Pdf(MinimalPages(StreamObj(4,
        "/Type/XObject/Subtype/Image/Width 1000/Height 1000/ColorSpace/DeviceGray/BitsPerComponent 8/Filter/FlateDecode",
        Zlib(new byte[decodedBytes]))));

    public static byte[] PdfWithLargeFlateNonImage(int decodedBytes) => Pdf(MinimalPages(StreamObj(4,
        "/Filter/FlateDecode", Zlib(new byte[decodedBytes]))));

    public static byte[] PdfWithLargeFlateImageAsAttachment(int decodedBytes) => Pdf(MinimalPages(StreamObj(4,
        "/Type/EmbeddedFile/Subtype/Image/Filter/FlateDecode", Zlib(new byte[decodedBytes]))));

    public static byte[] PdfWithDctOnNonImageStream() => Pdf(MinimalPages(StreamObj(4,
        "/Filter/DCTDecode", [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0xFF, 0xD9])));

    public static byte[] PdfWithDctEmbeddedFile() => Pdf(MinimalPages(StreamObj(4,
        "/Type/EmbeddedFile/Subtype/Image/Filter/DCTDecode",
        [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0xFF, 0xD9])));

    // --- 0.3.0: predictor PNG de /FlateDecode ---

    /// <summary>Codifica <paramref name="data"/> com predictor PNG (Colors 1, 8 bits) usando o filtro de linha indicado.</summary>
    public static byte[] PngPredict(byte[] data, int columns, int filterType)
    {
        int padded = (data.Length + columns - 1) / columns * columns;
        var rows = new byte[padded];
        Buffer.BlockCopy(data, 0, rows, 0, data.Length);

        var output = new byte[padded / columns * (columns + 1)];
        for (int row = 0; row < padded / columns; row++)
        {
            output[row * (columns + 1)] = (byte)filterType;
            for (int i = 0; i < columns; i++)
            {
                int cur = rows[row * columns + i];
                int left = i > 0 ? rows[row * columns + i - 1] : 0;
                int up = row > 0 ? rows[(row - 1) * columns + i] : 0;
                int upLeft = row > 0 && i > 0 ? rows[(row - 1) * columns + i - 1] : 0;
                int predicted = filterType switch
                {
                    0 => 0,
                    1 => left,
                    2 => up,
                    3 => (left + up) >> 1,
                    4 => PaethRef(left, up, upLeft),
                    _ => throw new ArgumentOutOfRangeException(nameof(filterType)),
                };
                output[row * (columns + 1) + 1 + i] = (byte)(cur - predicted);
            }
        }
        return output;
    }

    private static int PaethRef(int a, int b, int c)
    {
        int p = a + b - c, pa = Math.Abs(p - a), pb = Math.Abs(p - b), pc = Math.Abs(p - c);
        return pa <= pb && pa <= pc ? a : pb <= pc ? b : c;
    }

    /// <summary>Content stream com /JavaScript em claro, Flate + predictor PNG (a deteção só funciona se o predictor decodificar certo).</summary>
    public static byte[] PdfWithPredictedStreamHidingJavaScript(int filterType, int columns = 8)
    {
        byte[] plain = A("<</S/JavaScript/JS(app.alert\\('x'\\))>> 0123456789 abcdefghijklmnop");
        byte[] encoded = Zlib(PngPredict(plain, columns, filterType));
        return Pdf(MinimalPages(StreamObj(4,
            $"/Filter/FlateDecode/DecodeParms<</Predictor 15/Columns {columns}>>", encoded)));
    }

    /// <summary>PDF 1.5 com xref STREAM (como Acrobat/iText); <paramref name="predictor12"/> liga /Predictor 12 nele.</summary>
    public static byte[] PdfWithXrefStream(bool predictor12, string? decodeParmsOverride = null,
        Func<byte[], byte[]>? tamper = null)
    {
        string[] bodies =
        [
            "<</Type/Catalog/Pages 2 0 R>>",
            "<</Type/Pages/Kids[3 0 R]/Count 1>>",
            "<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>",
        ];

        using var output = new MemoryStream();
        void Write(byte[] bytes) => output.Write(bytes, 0, bytes.Length);

        Write(A("%PDF-1.5\n"));
        var offsets = new long[bodies.Length + 1];
        for (int i = 0; i < bodies.Length; i++)
        {
            offsets[i + 1] = output.Position;
            Write(A($"{i + 1} 0 obj\n{bodies[i]}\nendobj\n"));
        }

        long xrefOffset = output.Position;
        var entries = new List<byte>();
        void Row(byte type, long field2, byte gen)
        {
            entries.Add(type);
            entries.Add((byte)(field2 >> 16));
            entries.Add((byte)(field2 >> 8));
            entries.Add((byte)field2);
            entries.Add(gen);
        }

        Row(0, 0, 255);
        for (int i = 1; i <= bodies.Length; i++) Row(1, offsets[i], 0);
        Row(1, xrefOffset, 0);

        byte[] data = entries.ToArray();
        string parms = decodeParmsOverride ?? "";
        if (predictor12)
        {
            data = PngPredict(data, 5, 2);
            parms = decodeParmsOverride ?? "/DecodeParms<</Columns 5/Predictor 12>>";
        }
        if (tamper is not null) data = tamper(data);

        byte[] compressed = Zlib(data);
        Write(A($"4 0 obj\n<</Type/XRef/Size 5/W[1 3 1]/Root 1 0 R/Filter/FlateDecode{parms}/Length {compressed.Length}>>\nstream\n"));
        Write(compressed);
        Write(A("\nendstream\nendobj\n"));
        Write(A($"startxref\n{xrefOffset}\n%%EOF\n"));
        return output.ToArray();
    }

    /// <summary>Content stream BENIGNO com predictor PNG: o gêmeo "limpo" dos casos malformados (sem xref stream no caminho).</summary>
    public static byte[] PdfWithPredictedBenignStream(string? decodeParms = null,
        Func<byte[], byte[]>? tamper = null, bool withParmsObject = false, int rowFilter = 2)
    {
        byte[] predicted = PngPredict(A("BT (texto benigno) Tj ET 0123456789"), 8, rowFilter);
        if (tamper is not null) predicted = tamper(predicted);

        var objects = MinimalPages().ToList();
        objects.Add(StreamObj(4,
            $"/Filter/FlateDecode{decodeParms ?? "/DecodeParms<</Predictor 15/Columns 8>>"}", Zlib(predicted)));
        if (withParmsObject) objects.Add(Obj(9, "<</Predictor 15/Columns 8>>"));
        return Pdf(objects);
    }

    public static byte[] PdfWithAsciiFilterPredictor() => Pdf(MinimalPages(StreamObj(4,
        "/Filter[/ASCIIHexDecode]/DecodeParms[<</Predictor 12/Columns 1>>]", AsciiHex(A("dados")))));


    // --- 0.3.0 VOLTA r2: cobertura de bytes ---

    /// <summary>CleanPdf com <paramref name="between"/> (texto/whitespace/comentário) entre os objetos.</summary>
    public static byte[] PdfWithBetweenObjects(string between) =>
        Pdf(MinimalPages(), betweenObjects: between);

    /// <summary>xref apontando 2 bytes ANTES de cada objeto (no whitespace que o precede); o objeto 4 tem stream.</summary>
    public static byte[] PdfWithOffsetsPointingAtLeadingWhitespace() => Pdf(
        MinimalPages(StreamObj(4, string.Empty, A("BT ET"))), betweenObjects: "   ", offsetShift: 2);

    /// <summary>Caso "20": PDF + lixo + startxref FALSO apontando para o offset original + %%EOF.</summary>
    public static byte[] PdfWithGarbageAndFakeStartxref(byte[] garbage)
    {
        byte[] original = CleanPdf();
        string text = Encoding.ASCII.GetString(original);
        int start = text.LastIndexOf("startxref\n", StringComparison.Ordinal) + "startxref\n".Length;
        string offset = text[start..text.IndexOf('\n', start)];
        return Concat(original, garbage, A($"\nstartxref\n{offset}\n%%EOF\n"));
    }

    /// <summary>Caso "24": PDF + lixo + seção xref VAZIA com /Prev válido + startxref novo.</summary>
    public static byte[] PdfWithGarbageAndEmptyXrefSection(byte[] garbage)
    {
        byte[] original = CleanPdf();
        string text = Encoding.ASCII.GetString(original);
        int start = text.LastIndexOf("startxref\n", StringComparison.Ordinal) + "startxref\n".Length;
        string previous = text[start..text.IndexOf('\n', start)];
        long xrefOffset = original.Length + garbage.Length + 1;
        return Concat(original, garbage, A(
            $"\nxref\n0 0\ntrailer\n<</Size 4/Root 1 0 R/Prev {previous}>>\nstartxref\n{xrefOffset}\n%%EOF\n"));
    }

    /// <summary>Objeto SINTATICAMENTE válido, fora de qualquer xref, antes de um startxref falso.</summary>
    public static byte[] PdfWithOrphanObject(string body, byte[]? streamData = null)
    {
        byte[] orphan = streamData is null
            ? A($"\n9 0 obj\n{body}\nendobj")
            : Concat(A($"\n9 0 obj\n<<{body}/Length {streamData.Length}>>\nstream\n"), streamData, A("\nendstream\nendobj"));
        return PdfWithGarbageAndFakeStartxref(orphan);
    }

    /// <summary>Objeto livre (f) na xref: o Pdf() deixa os números ausentes como entradas f.</summary>
    public static byte[] PdfWithFreeEntries() => Pdf(
        Obj(1, "<</Type/Catalog/Pages 2 0 R>>"),
        Obj(2, "<</Type/Pages/Kids[3 0 R]/Count 1>>"),
        Obj(3, "<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>"),
        Obj(7, "<</Tipo/Teste>>"));

    /// <summary>
    /// Linearizado sintético: obj de linearização + xref da 1ª página (com /Prev) + startxref 0 no início,
    /// objetos, xref principal e startxref final apontando para a 1ª xref. <paramref name="between"/> entra
    /// entre dois objetos da 1ª página.
    /// </summary>
    public static byte[] PdfLinearizedSynthetic(string between = "")
    {
        long[] offsets = new long[5];
        long firstXref = 0, mainXref = 0;
        byte[] result = [];
        for (int pass = 0; pass < 2; pass++)
        {
            using var output = new MemoryStream();
            void Write(string text) { var b = Encoding.Latin1.GetBytes(text); output.Write(b, 0, b.Length); }
            string Entry(long offset) => $"{offset:0000000000} 00000 n \n";

            Write("%PDF-1.7\n%\u00E2\u00E3\u00CF\u00D3\n");
            offsets[4] = output.Position;
            Write("4 0 obj\n<</Linearized 1/L 0000000000/H[0 0]/O 3/E 0/N 1/T 0000000000>>\nendobj\n");
            firstXref = output.Position;
            Write("xref\n1 1\n" + Entry(offsets[1]) + "3 2\n" + Entry(offsets[3]) + Entry(offsets[4]));
            Write($"trailer\n<</Size 5/Root 1 0 R/Prev {mainXref:0000000000}>>\nstartxref\n0\n%%EOF\n");
            offsets[1] = output.Position;
            Write("1 0 obj\n<</Type/Catalog/Pages 2 0 R>>\nendobj\n");
            if (between.Length > 0) Write(between);
            offsets[3] = output.Position;
            Write("3 0 obj\n<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>\nendobj\n");
            offsets[2] = output.Position;
            Write("2 0 obj\n<</Type/Pages/Kids[3 0 R]/Count 1>>\nendobj\n");
            mainXref = output.Position;
            Write("xref\n0 1\n0000000000 65535 f \n2 1\n" + Entry(offsets[2]));
            Write($"trailer\n<</Size 5/Root 1 0 R>>\nstartxref\n{firstXref}\n%%EOF\n");
            result = output.ToArray();
        }
        return result;
    }

    // --- VOLTA r3: aninhamento profundo (a guarda de recursão precisa ter dente) ---

    /// <summary>Objeto cujo corpo é <paramref name="depth"/> níveis de [ ou &lt;&lt;/A, para estourar uma recursão sem limite.</summary>
    public static byte[] PdfWithDeepNesting(char kind, int depth)
    {
        string body = kind == '['
            ? new string('[', depth) + new string(']', depth)
            : string.Concat(Enumerable.Repeat("<</A", depth)) + "1" + string.Concat(Enumerable.Repeat(">>", depth));
        return Pdf(MinimalPages(Obj(4, body)));
    }

    /// <summary>Árvore /EmbeddedFiles com <paramref name="nodes"/> nós encadeados por /Kids (profundidade = nós).</summary>
    public static byte[] PdfWithDeepNameTree(int nodes)
    {
        var objects = new List<PdfObject>
        {
            Obj(1, "<</Type/Catalog/Pages 2 0 R/Names<</EmbeddedFiles 10 0 R>>>>"),
            Obj(2, "<</Type/Pages/Kids[3 0 R]/Count 1>>"),
            Obj(3, "<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>"),
        };
        for (int index = 0; index < nodes; index++)
        {
            int number = 10 + index;
            string limits = index == 0 ? "" : "/Limits[(a)(a)]";
            objects.Add(index == nodes - 1
                ? Obj(number, $"<</Names[(a)(arquivo.txt)]{limits}>>")
                : Obj(number, $"<</Kids[{number + 1} 0 R]{limits}>>"));
        }
        return Pdf(objects);
    }


    // --- VOLTA r4: ataques ao PdfDocument.Open do PdfPig (recursão sem limite -> stack overflow) ---

    private static PdfObject[] CatalogWith(string catalogExtra, params PdfObject[] extra)
    {
        var objects = new List<PdfObject>
        {
            Obj(1, $"<</Type/Catalog/Pages 2 0 R{catalogExtra}>>"),
            Obj(2, "<</Type/Pages/Kids[3 0 R]/Count 1>>"),
            Obj(3, "<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>"),
        };
        objects.AddRange(extra);
        return [.. objects];
    }

    /// <summary>Name tree /Names /Dests de <paramref name="nodes"/> nós encadeados por /Kids (último com /Names), opcionalmente fechando em ciclo.</summary>
    public static IEnumerable<(int Number, string Body)> DestsChain(int nodes, bool cycle = false)
    {
        for (int index = 0; index < nodes; index++)
        {
            int number = 10 + index;
            bool last = index == nodes - 1;
            string body = !last
                ? $"<</Kids[{number + 1} 0 R]>>"
                : cycle ? "<</Kids[10 0 R]>>" : "<</Names[(a)[3 0 R/Fit]]>>";
            yield return (number, body);
        }
    }

    private static PdfObject[] DestsObjects(IEnumerable<(int Number, string Body)> nodes) =>
        CatalogWith("/Names<</Dests 10 0 R>>", nodes.Select(n => Obj(n.Number, n.Body)).ToArray());

    public static byte[] PdfWithDests(int nodes, bool cycle = false) => Pdf(DestsObjects(DestsChain(nodes, cycle)));

    /// <summary>Cada nó repete o mesmo filho ([X X]): 2^n visitas se a estrutura for percorrida sem guarda.</summary>
    public static byte[] PdfWithDestsRepeatedKid(int levels) => Pdf(DestsObjects(
        Enumerable.Range(0, levels).Select(index => index == levels - 1
            ? (10 + index, "<</Names[(a)[3 0 R/Fit]]>>")
            : (10 + index, $"<</Kids[{11 + index} 0 R {11 + index} 0 R]>>"))));

    /// <summary>Dois nós por nível, ambos apontando para os dois do próximo (nó compartilhado; 2^n caminhos).</summary>
    public static byte[] PdfWithDestsDiamond(int levels)
    {
        var nodes = new List<(int, string)>();
        for (int level = 0; level < levels; level++)
        {
            int a = 10 + level * 2, b = a + 1;
            string body = level == levels - 1
                ? "<</Names[(a)[3 0 R/Fit]]>>"
                : $"<</Kids[{a + 2} 0 R {b + 2} 0 R]>>";
            nodes.Add((a, body));
            nodes.Add((b, body));
        }
        return Pdf(DestsObjects(nodes));
    }

    /// <summary>Árvore de páginas profunda: /Pages -> /Pages -> ... -> /Page (Parent coerente; passa na validação estrita do PdfPig).</summary>
    public static byte[] PdfWithDeepPageTree(int depth)
    {
        var objects = new List<PdfObject> { Obj(1, "<</Type/Catalog/Pages 2 0 R>>") };
        int previous = 1;
        for (int level = 0; level < depth; level++)
        {
            int number = 2 + level;
            string parent = level == 0 ? "" : $"/Parent {previous} 0 R";
            objects.Add(Obj(number, $"<</Type/Pages{parent}/Kids[{number + 1} 0 R]/Count 1>>"));
            previous = number;
        }
        int pageNumber = 2 + depth;
        objects.Add(Obj(pageNumber, $"<</Type/Page/Parent {previous} 0 R/MediaBox[0 0 612 792]>>"));
        return Pdf(objects);
    }

    /// <summary>Cadeia de apelidos (n 0 obj  m 0 R) a partir de /Pages, terminando (ou não, se <paramref name="cycle"/>) na árvore real.</summary>
    public static byte[] PdfWithAliasChain(int length, bool cycle = false, bool arrayWrapped = false)
    {
        string Ref(int n) => arrayWrapped ? $"[{n} 0 R]" : $"{n} 0 R";
        var objects = new List<PdfObject>
        {
            Obj(1, "<</Type/Catalog/Pages 20 0 R>>"),
            Obj(2, "<</Type/Pages/Kids[3 0 R]/Count 1>>"),
            Obj(3, "<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>"),
        };
        for (int index = 0; index < length; index++)
        {
            int number = 20 + index;
            int target = index == length - 1 ? (cycle ? 20 : 2) : number + 1;
            objects.Add(Obj(number, Ref(target)));
        }
        return Pdf(objects);
    }

    /// <summary>/Dests no estilo PDF 1.1 (dicionário plano no catálogo).</summary>
    public static byte[] PdfWithOldStyleDests() => Pdf(CatalogWith("/Dests 10 0 R",
        Obj(10, "<</Inicio[3 0 R/Fit]/Fim[3 0 R/XYZ 0 0 1]>>")));

    /// <summary>/Info (trailer) apontando para um apelido cíclico.</summary>
    public static byte[] PdfWithInfoAliasCycle() => Pdf(
        [.. MinimalPages(), Obj(30, "31 0 R"), Obj(31, "30 0 R")], trailerExtra: "/Info 30 0 R");

    /// <summary>Valor de /Info/Title que é o início de uma cadeia de apelidos (DirectObjectFinder.TryGet recursa sem teto).</summary>
    public static byte[] PdfWithInfoValueAliasChain(int length)
    {
        var objects = new List<PdfObject>(MinimalPages()) { Obj(30, "<</Title 31 0 R>>") };
        for (int index = 0; index < length; index++)
            objects.Add(Obj(31 + index, index == length - 1 ? "(fim)" : $"{32 + index} 0 R"));
        return Pdf(objects, trailerExtra: "/Info 30 0 R");
    }

    /// <summary>Valor de /Info que é um apelido que aponta para si mesmo.</summary>
    public static byte[] PdfWithInfoValueSelfAlias() => Pdf(
        [.. MinimalPages(), Obj(30, "<</Title 31 0 R>>"), Obj(31, "31 0 R")], trailerExtra: "/Info 30 0 R");

    /// <summary>Documento "moderno": xref stream + object stream com TODOS os objetos de <paramref name="members"/> (catálogo inclusive).</summary>
    public static byte[] PdfWithObjectStream(IReadOnlyList<(int Number, string Body)> members,
        string typePart = "/Type/ObjStm", string extraDictionary = "", string beforeObjectStream = "", bool containerFree = false)
    {
        var header = new StringBuilder();
        var content = new StringBuilder();
        foreach (var (number, body) in members)
        {
            header.Append($"{number} {content.Length} ");
            content.Append(Tx(body)).Append('\n');
        }

        string headerText = header.ToString();
        byte[] compressed = Zlib(A(headerText + content));
        int objectStreamNumber = members.Max(m => m.Number) + 1;
        int xrefNumber = objectStreamNumber + 1;

        using var output = new MemoryStream();
        void Write(byte[] bytes) => output.Write(bytes, 0, bytes.Length);

        Write(A("%PDF-1.7\n%\xE2\xE3\xCF\xD3\n"));
        Write(Encoding.Latin1.GetBytes(beforeObjectStream));
        long objectStreamOffset = output.Position;
        Write(A($"{objectStreamNumber} 0 obj\n<<{typePart}/N {members.Count}/First {headerText.Length}{extraDictionary}/Filter/FlateDecode/Length {compressed.Length}>>\nstream\n"));
        Write(compressed);
        Write(A("\nendstream\nendobj\n"));

        long xrefOffset = output.Position;
        int size = xrefNumber + 1;
        byte[] entries = new byte[size * 7];
        void Entry(int index, byte type, long field1, int field2)
        {
            int at = index * 7;
            entries[at] = type;
            entries[at + 1] = (byte)(field1 >> 24);
            entries[at + 2] = (byte)(field1 >> 16);
            entries[at + 3] = (byte)(field1 >> 8);
            entries[at + 4] = (byte)field1;
            entries[at + 5] = (byte)(field2 >> 8);
            entries[at + 6] = (byte)field2;
        }
        Entry(0, 0, 0, 65535);
        for (int index = 0; index < members.Count; index++) Entry(members[index].Number, 2, objectStreamNumber, index);
        if (containerFree) Entry(objectStreamNumber, 0, 0, 65535);
        else Entry(objectStreamNumber, 1, objectStreamOffset, 0);
        Entry(xrefNumber, 1, xrefOffset, 0);

        Write(A($"{xrefNumber} 0 obj\n<</Type/XRef/Size {size}/Root 1 0 R/W[1 4 2]/Index[0 {size}]/Length {entries.Length}>>\nstream\n"));
        Write(entries);
        Write(A($"\nendstream\nendobj\nstartxref\n{xrefOffset}\n%%EOF\n"));
        return output.ToArray();
    }

    public static IReadOnlyList<(int Number, string Body)> ObjectStreamDocument(string catalogExtra,
        IEnumerable<(int Number, string Body)> extra) =>
    [
        (1, $"<</Type/Catalog/Pages 2 0 R{catalogExtra}>>"),
        (2, "<</Type/Pages/Kids[3 0 R]/Count 1>>"),
        (3, "<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>"),
        .. extra,
    ];

    // --- VOLTA r5: contornos léxicos (X1..X5), L1, custo e revisões ---

    public static byte[] PdfWithDestsRaw(string node10, string node11) => Pdf(
        CatalogWith("/Names<</Dests 10 0 R>>", Obj(10, node10), Obj(11, node11)));

    /// <summary>Atualização incremental BEM formada (xref próprio + /Prev) que redefine os objetos dados.</summary>
    public static byte[] AppendUpdate(byte[] original, params (int Number, string Body)[] objects)
    {
        string text = Encoding.Latin1.GetString(original);
        int at = text.LastIndexOf("startxref\n", StringComparison.Ordinal) + "startxref\n".Length;
        string previous = text[at..text.IndexOf('\n', at)];

        using var output = new MemoryStream();
        output.Write(original, 0, original.Length);
        var offsets = new List<(int Number, long Offset)>();
        foreach (var (number, body) in objects)
        {
            offsets.Add((number, output.Position));
            byte[] bytes = A($"{number} 0 obj\n{Tx(body)}\nendobj\n");
            output.Write(bytes, 0, bytes.Length);
        }

        long xref = output.Position;
        var section = new StringBuilder("xref\n");
        foreach (var (number, offset) in offsets)
            section.Append($"{number} 1\n{offset:0000000000} 00000 n \n");
        section.Append($"trailer\n<</Size {offsets.Max(o => o.Number) + 1}/Root 1 0 R/Prev {previous}>>\nstartxref\n{xref}\n%%EOF\n");
        byte[] tail = A(section.ToString());
        output.Write(tail, 0, tail.Length);
        return output.ToArray();
    }

    /// <summary>X5: 10.001 definições-apelido do objeto 6 depois de uma árvore /Dests cíclica (o Resolve truncava em 10.000).</summary>
    public static byte[] PdfWithManyAliasDefinitions(int definitions)
    {
        byte[] original = Pdf(CatalogWith("/Names<</Dests 5 0 R>>",
            Obj(5, "<</Kids[6 0 R]>>"), Obj(6, "7 0 R"), Obj(7, "<</Kids[5 0 R]>>")));
        string text = Encoding.Latin1.GetString(original);
        int at = text.LastIndexOf("startxref\n", StringComparison.Ordinal) + "startxref\n".Length;
        string previous = text[at..text.IndexOf('\n', at)];
        var tail = new StringBuilder();
        for (int index = 0; index < definitions; index++) tail.Append($"6 0 obj\n{100000 + index} 0 R\nendobj\n");
        tail.Append($"startxref\n{previous}\n%%EOF\n");
        return Concat(original, A(tail.ToString()));
    }

    /// <summary>Custo: <paramref name="holders"/> objetos com /Kids[5 0 R] e o objeto 5 com muitas definições-apelido.</summary>
    public static byte[] PdfWithManyKidsHolders(int holders, int aliasDefinitions)
    {
        var objects = new List<PdfObject>(MinimalPages());
        for (int index = 0; index < holders; index++) objects.Add(Obj(100 + index, "<</Kids[5 0 R]>>"));
        byte[] original = Pdf(objects);
        string text = Encoding.Latin1.GetString(original);
        int at = text.LastIndexOf("startxref\n", StringComparison.Ordinal) + "startxref\n".Length;
        string previous = text[at..text.IndexOf('\n', at)];
        var tail = new StringBuilder();
        for (int index = 0; index < aliasDefinitions; index++) tail.Append($"5 0 obj\n{900000 + index} 0 R\nendobj\n");
        tail.Append($"startxref\n{previous}\n%%EOF\n");
        return Concat(original, A(tail.ToString()));
    }

    /// <summary>L1: atualização incremental LEGÍTIMA que reestrutura a árvore de páginas (a página 3 troca de pai).</summary>
    public static byte[] PdfWithPageTreeRestructuringUpdate() => AppendUpdate(CleanPdf(),
        (2, "<</Type/Pages/Kids[7 0 R]/Count 1>>"),
        (3, "<</Type/Page/Parent 7 0 R/MediaBox[0 0 612 792]>>"),
        (7, "<</Type/Pages/Parent 2 0 R/Kids[3 0 R]/Count 1>>"));

    /// <summary>
    /// Objetos /Dests cíclicos ESCONDIDOS dentro dos dados de um stream, alcançados por entradas da xref que
    /// apontam para dentro dele (o PdfPig lê o objeto no offset da xref, onde a varredura de nível superior só vê dados).
    /// </summary>
    public static byte[] PdfWithHiddenObjectsInsideStream()
    {
        using var output = new MemoryStream();
        void Write(byte[] bytes) => output.Write(bytes, 0, bytes.Length);
        var offsets = new Dictionary<int, long>();

        Write(A("%PDF-1.7\n"));
        void WriteObject(int number, string body)
        {
            offsets[number] = output.Position;
            Write(A($"{number} 0 obj\n{Tx(body)}\nendobj\n"));
        }

        WriteObject(1, "<</Type/Catalog/Pages 2 0 R/Names<</Dests 10 0 R>>>>");
        WriteObject(2, "<</Type/Pages/Kids[3 0 R]/Count 1>>");
        WriteObject(3, "<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>");

        string fake10 = Tx("10 0 obj\n<</Kids[11 0 R]>>\nendobj\n");
        string fake11 = Tx("11 0 obj\n<</Kids[10 0 R]>>\nendobj\n");
        string streamBody = "padding\n" + fake10 + fake11;
        offsets[4] = output.Position;
        Write(A($"4 0 obj\n<</Length {streamBody.Length}>>\nstream\n"));
        long dataStart = output.Position;
        Write(A(streamBody));
        Write(A("\nendstream\nendobj\n"));
        offsets[10] = dataStart + "padding\n".Length;
        offsets[11] = offsets[10] + fake10.Length;

        long xref = output.Position;
        var section = new StringBuilder($"xref\n0 12\n0000000000 65535 f \n");
        for (int number = 1; number <= 11; number++)
            section.Append(offsets.TryGetValue(number, out long offset)
                ? $"{offset:0000000000} 00000 n \n"
                : "0000000000 65535 f \n");
        section.Append($"trailer\n<</Size 12/Root 1 0 R>>\nstartxref\n{xref}\n%%EOF\n");
        Write(A(section.ToString()));
        return output.ToArray();
    }

    /// <summary>CleanPdf cujo startxref final aponta para um OBJETO (não para a seção xref): o PdfPig reconstruiria por força bruta.</summary>
    public static byte[] PdfWithStartxrefPointingAtAnObject()
    {
        byte[] original = CleanPdf();
        string text = Encoding.Latin1.GetString(original);
        int objectOffset = text.IndexOf("1 0 obj", StringComparison.Ordinal);
        int at = text.LastIndexOf("startxref\n", StringComparison.Ordinal) + "startxref\n".Length;
        int end = text.IndexOf('\n', at);
        return Encoding.Latin1.GetBytes(text[..at] + objectOffset + text[end..]);
    }

    /// <summary>Atualização incremental legítima, mas com /Prev apontando para um objeto em vez da seção xref anterior.</summary>
    public static byte[] PdfWithUpdatePrevPointingAtAnObject()
    {
        byte[] updated = AppendUpdate(CleanPdf(), (4, "<</Tipo/Teste>>"));
        string text = Encoding.Latin1.GetString(updated);
        int objectOffset = text.IndexOf("1 0 obj", StringComparison.Ordinal);
        int prev = text.LastIndexOf("/Prev ", StringComparison.Ordinal) + "/Prev ".Length;
        int end = text.IndexOf('>', prev);
        return Encoding.Latin1.GetBytes(text[..prev] + objectOffset + text[end..]);
    }

    // --- VOLTA r6: filhos DIRETOS em /Kids (Y1..Y3) e objetos escritos em dados de stream, fora da xref (B1/B3/B5) ---

    /// <summary>Y1/Y2: o ciclo passa por dicionários DIRETOS dentro de /Kids (<paramref name="directLevels"/> níveis).</summary>
    public static byte[] PdfWithDestsDirectKids(int directLevels)
    {
        string wrapped = "11 0 R";
        for (int level = 0; level < directLevels; level++) wrapped = $"<</Kids[{wrapped}]>>";
        return PdfWithDestsRaw($"<</Kids[{wrapped}]>>", "<</Kids[10 0 R]>>");
    }

    /// <summary>Y3: /Kids 12 0 R, e o objeto 12 é um array com um dicionário direto que continua o ciclo.</summary>
    public static byte[] PdfWithDestsKidsHeldByAnArrayWithDirectDictionary() => Pdf(
        CatalogWith("/Names<</Dests 10 0 R>>", Obj(10, "<</Kids 12 0 R>>"), Obj(11, "<</Kids[10 0 R]>>"),
            Obj(12, "[<</Kids[11 0 R]>>]")));

    /// <summary>
    /// B1/B3/B5: a árvore /Dests cíclica existe SÓ como texto "n g obj" dentro dos dados de um stream sem filtro, e os
    /// objetos 10/11 não estão na xref — o PdfPig cai em força bruta e os acha. <paramref name="xrefStyle"/>:
    /// "" = xref normal; "19" = entradas de 19 bytes; "headerspace" = espaço extra no cabeçalho da seção.
    /// </summary>
    public static byte[] PdfWithCycleOnlyInsideStreamData(string xrefStyle = "")
    {
        byte[] body = A(Tx("10 0 obj\n<</Kids[11 0 R]>>\nendobj\n11 0 obj\n<</Kids[10 0 R]>>\nendobj\n"));
        var stream = new PdfObject(4, Concat(A($"<</Length {body.Length}>>\nstream\n"), body, A("\nendstream")));
        return Pdf(CatalogWith("/Names<</Dests 10 0 R>>", stream).ToList(), xrefStyle: xrefStyle);
    }

    /// <summary>Referência para um objeto livre EXPLÍCITO na xref (o Pdf() lista os números ausentes como "f").</summary>
    public static byte[] PdfWithFreeEntryReferenced() => Pdf(
        CatalogWith("/Names<</Dests 10 0 R>>", Obj(10, "<</Names[(a)[3 0 R/Fit]]/Limits[(a)(a)]/Extra 7 0 R>>"), Obj(8, "<</Tipo/Teste>>")));

    public static byte[] PdfWithInfoPointingAtAnUnlistedObject() => Pdf(
        [.. MinimalPages(), Obj(30, "<</Title(x)>>")], trailerExtra: "/Info 99 0 R");

    /// <summary>Stream SEM filtro com <paramref name="data"/> nos dados (objeto 4).</summary>
    public static byte[] PdfWithUnfilteredStreamData(string data) => Pdf(MinimalPages(StreamObj(4, "", A(data))));

    // --- VOLTA r7: força bruta com objetos LIVRES (F1..F3), e os casos que voltam a Clean (LB, LC, LD) ---

    private const string HiddenCycleText =
        "10 0 obj\n<</Kids[11 0 R]>>\nendobj\n11 0 obj\n<</Kids[10 0 R]>>\nendobj\n";

    /// <summary>
    /// F1/F2/F3: o ciclo "10 0 obj…11 0 obj…" existe só como TEXTO escondido num lugar que a gramática de nível superior
    /// salta — dados DCT de uma imagem, comentário "%" ou string literal — e 10/11 são entradas LIVRES (f) da xref.
    /// </summary>
    public static byte[] PdfWithCycleHiddenAndMarkedFree(string where)
    {
        var objects = CatalogWith("/Names<</Dests 10 0 R>>", Obj(12, "<</Tipo/Teste>>")).ToList();
        string text = Tx(HiddenCycleText);
        string between = "";
        switch (where)
        {
            case "dct":
                byte[] jpeg = Concat([0xFF, 0xD8, 0xFF, 0xE0], A(text), [0xFF, 0xD9]);
                objects.Add(StreamObj(5, "/Type/XObject/Subtype/Image/Width 1/Height 1/ColorSpace/DeviceGray/BitsPerComponent 8/Filter/DCTDecode", jpeg));
                break;
            case "comment":
                between = "%" + text.Replace("\n", " ") + "\n";
                break;
            case "string":
                objects.Add(Obj(5, $"<</Title({text.Replace("\n", " ")})>>"));
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(where));
        }
        return Pdf(objects, betweenObjects: between);
    }

    // --- VOLTA r8: precedência da força bruta sobre a xref (T1..T6) ---

    private const string HiddenCopyOfNode11 = "11 0 obj\n<</Kids[10 0 R]>>\nendobj\n";

    /// <summary>
    /// T1/T2/T3: os nós 10 e 11 estão EM USO e são benignos (10 -> 11 -> folha); a cópia OCULTA de
    /// "11 0 obj &lt;&lt;/Kids[10 0 R]&gt;&gt;" (string, comentário ou dados DCT) fecharia um ciclo se o PdfPig a lesse.
    /// <paramref name="trigger"/>: "dangling" (catálogo com 98 0 R), "generation" (10 1 R), "mismatch" (offsets das
    /// entradas 10 e 11 trocados) ou "none" (nenhum gatilho de força bruta).
    /// </summary>
    public static byte[] PdfWithHiddenCopyOfInUseNode(string where, string trigger)
    {
        string catalogExtra = trigger switch
        {
            "dangling" => "/Names<</Dests 10 0 R>>/Zzz 98 0 R",
            "generation" => "/Names<</Dests 10 1 R>>",
            _ => "/Names<</Dests 10 0 R>>",
        };
        var objects = CatalogWith(catalogExtra, Obj(10, "<</Kids[11 0 R]>>"), Obj(11, "<</Names[(a)[3 0 R/Fit]]>>")).ToList();
        string text = Tx(HiddenCopyOfNode11);
        string between = "";
        switch (where)
        {
            case "dct":
                byte[] jpeg = Concat([0xFF, 0xD8, 0xFF, 0xE0], A(text), [0xFF, 0xD9]);
                objects.Add(StreamObj(5, "/Type/XObject/Subtype/Image/Width 1/Height 1/ColorSpace/DeviceGray/BitsPerComponent 8/Filter/DCTDecode", jpeg));
                break;
            case "comment":
                between = "%" + text.Replace("\n", " ") + "\n";
                break;
            case "string":
                objects.Add(Obj(5, $"<</Title({text.Replace("\n", " ")})>>"));
                break;
            case "none":
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(where));
        }

        byte[] pdf = Pdf(objects, betweenObjects: between);
        if (trigger != "mismatch") return pdf;

        // troca os offsets das entradas 10 e 11 da tabela xref (cada uma passa a apontar para o objeto da outra)
        string xrefText = Encoding.Latin1.GetString(pdf);
        int table = xrefText.LastIndexOf("\nxref\n", StringComparison.Ordinal) + 1;
        string[] lines = xrefText[table..].Split('\n');
        // lines: "xref", "0 N", "<cabeça livre>", entradas 1..N-1 a partir do índice 3
        string entry10 = lines[3 + 9];
        string entry11 = lines[3 + 10];
        lines[3 + 9] = entry11[..10] + entry10[10..];
        lines[3 + 10] = entry10[..10] + entry11[10..];
        return Encoding.Latin1.GetBytes(xrefText[..table] + string.Join("\n", lines));
    }

    /// <summary>
    /// T7/T8: o object stream (nº 12) tem uma CÓPIA OCULTA, numa string de um objeto solto, em que o nó 11 fecha um ciclo.
    /// <paramref name="trigger"/>: "dangling" (98 0 R), "containerFree" (o container é entrada LIVRE: o PdfPig só acha o 12
    /// pela cópia oculta) ou "none".
    /// </summary>
    public static byte[] PdfWithHiddenCopyOfTheObjectStream(string trigger)
    {
        string catalogExtra = "/Names<</Dests 10 0 R>>" + (trigger == "dangling" ? "/Zzz 98 0 R" : "");
        var members = ObjectStreamDocument(catalogExtra,
            [(10, "<</Kids[11 0 R]>>"), (11, "<</Names[(a)[3 0 R/Fit]]>>")]).ToList();

        var hiddenMembers = members.Select(m => m.Number == 11 ? (11, "<</Kids[10 0 R]>>") : m).ToList();
        var header = new StringBuilder();
        var content = new StringBuilder();
        foreach (var (number, body) in hiddenMembers)
        {
            header.Append($"{number} {content.Length} ");
            content.Append(Tx(body)).Append('\n');
        }

        int container = members.Max(m => m.Number) + 1;
        string hidden = $"{container} 0 obj\n<</Type/ObjStm/N {hiddenMembers.Count}/First {header.Length}/Length {content.Length}>>\n" +
                        $"stream\n{header}{content}\nendstream\nendobj\n";
        string orphan = $"5 0 obj\n<</Title({hidden})>>\nendobj\n";
        if (trigger == "containerFreeNoCopy") orphan = "";
        return PdfWithObjectStream(members, beforeObjectStream: orphan, containerFree: trigger is "containerFree" or "containerFreeNoCopy");
    }

    /// <summary>
    /// T9: ciclo de /Prev (a seção aponta para si mesma): o PdfPig descarta a xref inteira e usa o XrefBruteForcer
    /// para TODOS os objetos; <paramref name="hiddenCopy"/> acrescenta a cópia oculta do nó 11 (em string).
    /// </summary>
    public static byte[] PdfWithSelfReferencingPrev(bool hiddenCopy, bool interleaved = false)
    {
        var objects = CatalogWith("/Names<</Dests 10 0 R>>", Obj(10, "<</Kids[11 0 R]>>"), Obj(11, "<</Names[(a)[3 0 R/Fit]]>>")).ToList();
        // interleaved: "11 x 0 obj" — o XrefBruteForcer do PdfPig aceita lixo entre os dois números (o BruteForceSearcher não)
        string hidden = interleaved ? HiddenCopyOfNode11.Replace("11 0 obj", "11 x 0 obj") : HiddenCopyOfNode11;
        if (hiddenCopy) objects.Add(Obj(5, $"<</Title( {Tx(hidden).Replace("\n", " ")})>>"));
        string text = Encoding.Latin1.GetString(Pdf(objects));
        int at = text.LastIndexOf("startxref\n", StringComparison.Ordinal) + "startxref\n".Length;
        string xrefOffset = text[at..text.IndexOf('\n', at)];
        text = text.Replace("/Root 1 0 R>>", $"/Root 1 0 R/Prev {xrefOffset}>>");
        return Encoding.Latin1.GetBytes(text);
    }

    /// <summary>
    /// O1/O0 (r9): os nós 10 e 11 só estão listados numa seção "xref … trailer" ÓRFÃ (fora da cadeia startxref/Prev: o
    /// PdfPig a ignora) e são LIVRES (f) na seção principal; <paramref name="hiddenCopy"/> acrescenta a cópia oculta do
    /// nó 11 numa string. Os objetos 10 e 11 existem no arquivo e são benignos.
    /// </summary>
    public static byte[] PdfWithOrphanXrefSection(bool hiddenCopy, bool freeInMain = true)
    {
        var objects = CatalogWith("/Names<</Dests 10 0 R>>", Obj(10, "<</Kids[11 0 R]>>"), Obj(11, "<</Names[(a)[3 0 R/Fit]]>>")).ToList();
        if (hiddenCopy) objects.Add(Obj(5, $"<</Title( {Tx(HiddenCopyOfNode11).Replace("\n", " ")})>>"));
        string text = Encoding.Latin1.GetString(Pdf(objects));
        int table = text.LastIndexOf("\nxref\n", StringComparison.Ordinal) + 1;
        string[] lines = text[table..].Split('\n');
        string entry10 = lines[3 + 9];
        string entry11 = lines[3 + 10];
        const string Free = "0000000000 65535 f ";
        if (freeInMain)
        {
            lines[3 + 9] = Free;
            lines[3 + 10] = Free;
        }

        string orphan = $"xref\n10 2\n{entry10}\n{entry11}\ntrailer\n<</Size 12/Root 1 0 R>>\n";
        string main = string.Join("\n", lines);
        int oldStartxref = table;
        string rebuilt = text[..table] + orphan + main;
        rebuilt = rebuilt.Replace($"startxref\n{oldStartxref}\n", $"startxref\n{table + orphan.Length}\n");
        return Encoding.Latin1.GetBytes(rebuilt);
    }

    /// <summary>LB: referência para um objeto AUSENTE da xref, sem nenhum "N g obj" escondido (o PdfPig resolve para null).</summary>
    public static byte[] PdfWithDanglingReferenceWithoutHiddenObject() => Pdf(
        CatalogWith("/Names<</Dests 10 0 R>>", Obj(10, "<</Names[(a)[99 0 R/Fit]]>>")));

    /// <summary>LD: PDF ANEXADO sem compressão (os "N g obj" dele aparecem nos dados do anexo).</summary>
    public static byte[] PdfWithUncompressedEmbeddedPdf() => Pdf(MinimalPages(StreamObj(4, "/Type/EmbeddedFile", CleanPdf())));

    /// <summary>
    /// Objeto 10 definido NORMALMENTE no arquivo (início de objeto da cobertura), mas marcado LIVRE (f) na xref e
    /// referenciado: o PdfPig o acha por força bruta — e como a guarda também o leu, não há nada escondido.
    /// </summary>
    public static byte[] PdfWithObjectDefinedInFileButMarkedFree()
    {
        byte[] original = Pdf(CatalogWith("/Names<</Dests 10 0 R>>", Obj(12, "<</Tipo/Teste>>")));
        string text = Encoding.Latin1.GetString(original);
        int at = text.LastIndexOf("startxref\n", StringComparison.Ordinal) + "startxref\n".Length;
        string previous = text[at..text.IndexOf('\n', at)];
        string tail = "10 0 obj\n<</Names[(a)[3 0 R/Fit]]>>\nendobj\n" + $"startxref\n{previous}\n%%EOF\n";
        return Concat(original, A(tail));
    }

    // bytes "MZ" (executável) como lixo
    public static byte[] MzGarbage() => Concat([0x0A], Mz, A("  stub  "));

    // --- Executável ---
    public static byte[] ExeBytes() => Concat(Mz, A("  stub para deteccao de tipo  "));
}
