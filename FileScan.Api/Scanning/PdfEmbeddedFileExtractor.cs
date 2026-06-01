using System.IO.Compression;

namespace FileScan.Scanning;

/// <summary>
/// Extrai o conteúdo dos arquivos embutidos (/EmbeddedFile) de um PDF, para inspeção recursiva.
/// Pela spec do PDF, objetos de stream (como anexos) NÃO podem ficar dentro de object streams
/// comprimidos (/ObjStm) — então aparecem sempre em bytes crus, e a extração por varredura é confiável.
/// </summary>
internal static class PdfEmbeddedFileExtractor
{
    private const int MaxEmbedded = 50;
    private const int MaxContentBytes = 16 * 1024 * 1024;

    public static List<byte[]> Extract(byte[] pdf)
    {
        var results = new List<byte[]>();
        ReadOnlySpan<byte> span = pdf;
        ReadOnlySpan<byte> token = "/EmbeddedFile"u8;
        ReadOnlySpan<byte> streamKw = "stream"u8;
        ReadOnlySpan<byte> endStreamKw = "endstream"u8;
        ReadOnlySpan<byte> endObjKw = "endobj"u8;

        int from = 0;
        while (results.Count < MaxEmbedded)
        {
            int i = IndexOf(span, token, from);
            if (i < 0) break;

            int after = i + token.Length;
            from = after;
            if (after < span.Length && !IsDelimiter(span[after])) continue; // exclui "/EmbeddedFiles"

            int s = IndexOf(span, streamKw, after);
            if (s < 0) break;

            int eo = IndexOf(span, endObjKw, after);
            if (eo >= 0 && eo < s) continue; // sem stream no mesmo objeto = referência, não o anexo

            int dataStart = s + streamKw.Length;
            if (dataStart < span.Length && span[dataStart] == (byte)'\r') dataStart++;
            if (dataStart < span.Length && span[dataStart] == (byte)'\n') dataStart++;

            int e = IndexOf(span, endStreamKw, dataStart);
            if (e < 0) break;

            int dataEnd = e;
            if (dataEnd > dataStart && span[dataEnd - 1] == (byte)'\n') dataEnd--;
            if (dataEnd > dataStart && span[dataEnd - 1] == (byte)'\r') dataEnd--;

            if (dataEnd > dataStart)
                results.Add(Inflate(pdf, dataStart, dataEnd - dataStart) ?? pdf[dataStart..dataEnd]);

            from = e + endStreamKw.Length;
        }

        return results;
    }

    // FlateDecode (zlib) ou raw deflate; null se não for comprimido (aí o chamador usa os bytes crus).
    private static byte[]? Inflate(byte[] data, int offset, int length)
        => Decompress(data, offset, length, zlib: true) ?? Decompress(data, offset, length, zlib: false);

    private static byte[]? Decompress(byte[] data, int offset, int length, bool zlib)
    {
        try
        {
            using var input = new MemoryStream(data, offset, length, writable: false);
            using Stream dec = zlib
                ? new ZLibStream(input, CompressionMode.Decompress)
                : new DeflateStream(input, CompressionMode.Decompress);
            using var output = new MemoryStream();

            var buf = new byte[81920];
            int total = 0, read;
            while ((read = dec.Read(buf, 0, buf.Length)) > 0)
            {
                total += read;
                if (total > MaxContentBytes) { output.Write(buf, 0, read - (total - MaxContentBytes)); break; }
                output.Write(buf, 0, read);
            }

            return output.Length > 0 ? output.ToArray() : null;
        }
        catch
        {
            return null;
        }
    }

    private static bool IsDelimiter(byte b) =>
        b is (byte)' ' or (byte)'\t' or (byte)'\r' or (byte)'\n' or 0x0C or 0x00
          or (byte)'(' or (byte)')' or (byte)'<' or (byte)'>' or (byte)'[' or (byte)']'
          or (byte)'{' or (byte)'}' or (byte)'/' or (byte)'%';

    private static int IndexOf(ReadOnlySpan<byte> hay, ReadOnlySpan<byte> needle, int start)
    {
        if (start < 0 || start >= hay.Length) return -1;
        int rel = hay[start..].IndexOf(needle);
        return rel < 0 ? -1 : start + rel;
    }
}
