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

    private static PdfObject Obj(int number, string body) => new(number, A(body));

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
    private static byte[] Pdf(IEnumerable<PdfObject> source, string trailerExtra = "")
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
        }

        long xref = output.Position;
        Write(A($"xref\n0 {maxObject + 1}\n"));
        Write(A("0000000000 65535 f \n"));
        for (int number = 1; number <= maxObject; number++)
        {
            if (offsets.TryGetValue(number, out long offset))
                Write(A($"{offset:0000000000} 00000 n \n"));
            else
                Write(A("0000000000 65535 f \n"));
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

    public static byte[] PdfWithFilterChain()
    {
        var payload = Zlib(A("dados"));
        return Pdf(MinimalPages(StreamObj(4,
            "/Filter[/FlateDecode/ASCII85Decode]", payload)));
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

    // --- Executável ---
    public static byte[] ExeBytes() => Concat(Mz, A("  stub para deteccao de tipo  "));
}
