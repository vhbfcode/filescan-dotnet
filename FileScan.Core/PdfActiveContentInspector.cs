using System.IO.Compression;
using System.Text;

namespace FileScan.Scanning;

/// <summary>
/// Heurística de conteúdo ativo em PDF. Não é antivírus: procura os marcadores que tornam
/// um PDF "armado" (JavaScript, ações automáticas, anexos, execução externa) — a classe que
/// o AV por assinatura não pega quando o payload é novo/personalizado.
///
/// O arquivo é segmentado: as regiões ESTRUTURAIS (dicionários/objetos, onde os nomes ativos
/// realmente moram) são varridas cruas; os corpos de stream são SEMPRE descomprimidos antes de
/// qualquer validação — bytes comprimidos nunca são julgados crus, porque dados comprimidos são
/// estatisticamente aleatórios e produzem falsos positivos (um "/JS" por acaso, ou um "#XX" que a
/// normalização de nomes sintetizaria em marcador). Corpo que não descomprime: sem /Filter
/// declarado é literal e é varrido cru; com /Filter (não-Flate/criptografado) é ilegível e não é
/// inspecionado. Limitações conscientes: PDFs criptografados e filtros exóticos (LZW,
/// encadeamentos) podem escapar — aí a resposta é CDR.
/// </summary>
public static class PdfActiveContentInspector
{
    private const int MaxStreams = 200; // cap de DESCOMPRESSÕES por PDF (cap de bytes vem por parâmetro)

    // Marcadores de conteúdo ATIVO/perigoso. Nomes de PDF são case-sensitive, então a busca é exata.
    // /OpenAction e /AA: removidos (benignos — zoom/transições — e davam FP com subset de fonte tipo
    // "/AAAAAA+Lato-Bold"). /EmbeddedFile: NÃO está aqui — anexos são inspecionados recursivamente em
    // FileScanService (anexo benigno passa; exe/script/macro embutido é pego). Aqui ficam só os ativos.
    private static readonly (byte[] Token, string Label)[] Markers =
    [
        (Encoding.ASCII.GetBytes("/JavaScript"),   "JavaScript (/JavaScript)"),
        (Encoding.ASCII.GetBytes("/JS"),           "JavaScript (/JS)"),
        (Encoding.ASCII.GetBytes("/Launch"),       "execução de programa externo (/Launch)"),
    ];

    public static IReadOnlyList<string> Inspect(byte[] content,
        long maxDecompressedBytesPerStream = FileScannerOptions.DefaultMaxDecompressedBytesPerStream)
    {
        var found = new List<string>();
        var seen = new HashSet<string>();

        ReadOnlySpan<byte> span = content;
        ReadOnlySpan<byte> streamKw = "stream"u8;
        ReadOnlySpan<byte> endKw = "endstream"u8;

        int pos = 0;       // início da região estrutural corrente
        int inflations = 0; // descompressões tentadas (cap de CPU)

        while (seen.Count < Markers.Length)
        {
            // Próximo "stream" real (ignora o sufixo de "endstream").
            int s = IndexOf(span, streamKw, pos);
            while (s >= 3 && span[s - 1] == (byte)'d' && span[s - 2] == (byte)'n' && span[s - 3] == (byte)'e')
                s = IndexOf(span, streamKw, s + streamKw.Length);
            if (s < 0) break; // sem mais streams: o resto é estrutural

            int segStart = pos;
            int dataStart = s + streamKw.Length;
            if (dataStart < span.Length && span[dataStart] == (byte)'\r') dataStart++;
            if (dataStart < span.Length && span[dataStart] == (byte)'\n') dataStart++;

            // Região estrutural até o início do corpo (inclui o dicionário do stream).
            ScanRegion(span[segStart..Math.Min(dataStart, span.Length)], found, seen);

            int e = IndexOf(span, endKw, dataStart);
            if (e < 0)
            {
                // "stream" sem "endstream" (truncado/malformado): falha para o lado da DETECÇÃO —
                // varre o restante cru em vez de ignorá-lo.
                ScanRegion(span[dataStart..], found, seen);
                return found;
            }

            int dataEnd = e;
            if (dataEnd > dataStart && span[dataEnd - 1] == (byte)'\n') dataEnd--;
            if (dataEnd > dataStart && span[dataEnd - 1] == (byte)'\r') dataEnd--;

            if (dataEnd > dataStart)
            {
                byte[]? inflated = null;
                if (inflations < MaxStreams)
                {
                    inflations++;
                    inflated = TryInflate(content, dataStart, dataEnd - dataStart, maxDecompressedBytesPerStream);
                }

                if (inflated is not null)
                    ScanRegion(inflated, found, seen); // conteúdo real, descomprimido
                else if (!HasDeclaredFilter(span, segStart, s))
                    ScanRegion(span[dataStart..dataEnd], found, seen); // stream literal (sem filtro)
                // senão: /Filter não-Flate ou criptografado — bytes codificados não são
                // interpretáveis; julgá-los crus só produz falso positivo (limitação documentada).
            }

            pos = e + endKw.Length;
        }

        // Região estrutural final (trailer/xref — ou o arquivo inteiro, se não há streams).
        if (seen.Count < Markers.Length && pos < span.Length)
            ScanRegion(span[pos..], found, seen);

        return found;
    }

    private static void ScanRegion(ReadOnlySpan<byte> data, List<string> found, HashSet<string> seen)
        => ScanInto(NormalizePdfNames(data), found, seen);

    /// <summary>
    /// O dicionário do stream declara /Filter? Procura no trecho entre o último "obj" antes do
    /// "stream" e o próprio "stream" (normalizado — /F#69lter também conta). Sem /Filter, o corpo
    /// é literal e deve ser varrido cru; em dúvida (malformado), responde false — falha para o
    /// lado da detecção.
    /// </summary>
    private static bool HasDeclaredFilter(ReadOnlySpan<byte> span, int segStart, int streamKwStart)
    {
        if (streamKwStart <= segStart) return false;
        var window = span[segStart..streamKwStart];
        int objIdx = window.LastIndexOf("obj"u8);
        if (objIdx >= 0) window = window[objIdx..];
        return ContainsNameToken(NormalizePdfNames(window), "/Filter"u8);
    }

    /// <summary>
    /// Retorna uma cópia do buffer onde, DENTRO de tokens de nome PDF (iniciados por '/'),
    /// sequências '#XX' (dois dígitos hex) são decodificadas para o byte correspondente.
    /// Bytes FORA de nomes são copiados literalmente — isso evita falsos positivos causados por
    /// '#' em dados binários comprimidos.
    /// Shortcut: se não há '#' no buffer, devolve o array original sem alocação extra.
    /// </summary>
    private static byte[] NormalizePdfNames(ReadOnlySpan<byte> data)
    {
        // Shortcut: sem '#' não há nada a decodificar.
        if (data.IndexOf((byte)'#') < 0)
            return data.ToArray();

        var result = new byte[data.Length]; // tamanho máximo (pode encolher)
        int w = 0;        // posição de escrita no resultado
        bool inName = false;

        for (int r = 0; r < data.Length; r++)
        {
            byte b = data[r];

            if (!inName)
            {
                result[w++] = b;
                if (b == (byte)'/')
                    inName = true;
            }
            else
            {
                // '/' é delimitador: encerra o nome atual e inicia um novo imediatamente.
                if (IsPdfDelimiter(b))
                {
                    result[w++] = b;
                    // '/' inicia o próximo nome; qualquer outro delimitador termina sem iniciar.
                    inName = b == (byte)'/';
                }
                else if (b == (byte)'#' && r + 2 < data.Length
                         && IsHexDigit(data[r + 1]) && IsHexDigit(data[r + 2]))
                {
                    // Decodifica #XX → byte
                    result[w++] = (byte)((HexVal(data[r + 1]) << 4) | HexVal(data[r + 2]));
                    r += 2; // avança sobre os dois dígitos hex
                }
                else
                {
                    result[w++] = b;
                }
            }
        }

        return result[..w];
    }

    private static bool IsHexDigit(byte b) =>
        (b >= (byte)'0' && b <= (byte)'9') ||
        (b >= (byte)'a' && b <= (byte)'f') ||
        (b >= (byte)'A' && b <= (byte)'F');

    private static int HexVal(byte b) =>
        b >= (byte)'a' ? b - (byte)'a' + 10 :
        b >= (byte)'A' ? b - (byte)'A' + 10 :
                         b - (byte)'0';

    private static void ScanInto(ReadOnlySpan<byte> data, List<string> found, HashSet<string> seen)
    {
        foreach (var (token, label) in Markers)
        {
            if (seen.Contains(label)) continue;
            if (ContainsNameToken(data, token))
            {
                found.Add(label);
                seen.Add(label);
            }
        }
    }

    /// <summary>
    /// Procura o token como um nome de objeto PDF COMPLETO: o caractere seguinte precisa ser um
    /// delimitador/espaço do PDF (ou o fim do buffer). Evita casar com nomes maiores — ex.: "/JS"
    /// dentro de "/JSABCD+Fonte" ou "/AA" dentro de "/AAAAAA+Lato-Bold".
    /// </summary>
    private static bool ContainsNameToken(ReadOnlySpan<byte> data, ReadOnlySpan<byte> token)
    {
        int from = 0;
        while (from <= data.Length - token.Length)
        {
            int rel = data[from..].IndexOf(token);
            if (rel < 0) return false;

            int idx = from + rel;
            int after = idx + token.Length;
            if (after >= data.Length || IsPdfDelimiter(data[after]))
                return true;

            from = idx + 1;
        }
        return false;
    }

    // Espaços e delimitadores que terminam um nome de objeto PDF.
    private static bool IsPdfDelimiter(byte b) =>
        b is (byte)' ' or (byte)'\t' or (byte)'\r' or (byte)'\n' or 0x0C or 0x00
          or (byte)'(' or (byte)')' or (byte)'<' or (byte)'>' or (byte)'[' or (byte)']'
          or (byte)'{' or (byte)'}' or (byte)'/' or (byte)'%';

    private static byte[]? TryInflate(byte[] data, int offset, int length, long maxDecompressedBytes)
    {
        // FlateDecode normalmente vem com header zlib (0x78 ...); tenta zlib e cai para raw deflate.
        return Decompress<ZLibStream>(data, offset, length, maxDecompressedBytes)
            ?? Decompress<DeflateStream>(data, offset, length, maxDecompressedBytes);
    }

    private static byte[]? Decompress<T>(byte[] data, int offset, int length, long maxDecompressedBytes) where T : Stream
    {
        try
        {
            using var input = new MemoryStream(data, offset, length, writable: false);
            using Stream decompressor = typeof(T) == typeof(ZLibStream)
                ? new ZLibStream(input, CompressionMode.Decompress)
                : new DeflateStream(input, CompressionMode.Decompress);
            using var output = new MemoryStream();

            var buffer = new byte[81920];
            int total = 0, read;
            while ((read = decompressor.Read(buffer, 0, buffer.Length)) > 0)
            {
                total += read;
                if (total > maxDecompressedBytes)
                {
                    output.Write(buffer, 0, (int)(read - (total - maxDecompressedBytes)));
                    break;
                }
                output.Write(buffer, 0, read);
            }

            return output.ToArray();
        }
        catch
        {
            // não era deflate / criptografado / outro filtro — ignora
            return null;
        }
    }

    private static int IndexOf(ReadOnlySpan<byte> hay, ReadOnlySpan<byte> needle, int start)
    {
        if (start < 0 || start >= hay.Length) return -1;
        int rel = hay[start..].IndexOf(needle);
        return rel < 0 ? -1 : start + rel;
    }
}
