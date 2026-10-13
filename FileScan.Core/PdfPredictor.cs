using UglyToad.PdfPig.Tokens;

namespace FileScan.Scanning;

/// <summary>
/// Predictors PNG (/Predictor 10..15) de /FlateDecode. São a forma comum de xref streams e imagens de
/// PDFs de Acrobat/iText/Word. O predictor nunca EXPANDE (cada linha perde o byte de filtro), então o
/// orçamento de descompressão, já cobrado na inflação, continua sendo o teto. TIFF (/Predictor 2),
/// parâmetros não numéricos/indiretos e qualquer inconsistência de geometria falham fechados.
/// </summary>
internal static class PdfPredictor
{
    private const long MaxRowBytes = 64L * 1024 * 1024;

    internal readonly record struct Parameters(int Colors, int BitsPerComponent, int Columns);

    /// <summary>
    /// Lê /DecodeParms do filtro <paramref name="filterIndex"/>. Devolve null quando não há predictor
    /// (ausente, null ou /Predictor 1) e lança <see cref="PdfInspectionException"/> para todo o resto
    /// que não seja predictor PNG bem formado.
    /// </summary>
    public static Parameters? Read(DictionaryToken streamDictionary, int filterIndex)
    {
        if (!streamDictionary.TryGet(NameToken.DecodeParms, out IToken? decodeParms)
            || decodeParms is NullToken)
            return null;

        IToken? entry = decodeParms;
        if (decodeParms is ArrayToken array)
        {
            if (filterIndex >= array.Data.Count) return null;
            entry = array.Data[filterIndex];
            if (entry is NullToken) return null;
        }

        if (entry is not DictionaryToken parameters)
            throw new PdfInspectionException("predictor /DecodeParms não suportado");

        if (!parameters.TryGet(NameToken.Predictor, out IToken? predictorToken))
            return null;

        int predictor = ReadInt(predictorToken, "/Predictor");
        if (predictor == 1) return null;
        if (predictor is < 10 or > 15)
            throw new PdfInspectionException($"predictor /DecodeParms {predictor} não suportado");

        int colors = ReadOptionalInt(parameters, "Colors", 1);
        int bitsPerComponent = ReadOptionalInt(parameters, "BitsPerComponent", 8);
        int columns = ReadOptionalInt(parameters, "Columns", 1);

        if (colors is < 1 or > 32
            || bitsPerComponent is not (1 or 2 or 4 or 8 or 16)
            || columns < 1)
            throw new PdfInspectionException("parâmetros do predictor PNG inválidos");

        return new Parameters(colors, bitsPerComponent, columns);
    }

    public static byte[] ApplyPng(byte[] data, Parameters parameters)
    {
        long rowBytes = ((long)parameters.Colors * parameters.BitsPerComponent * parameters.Columns + 7) / 8;
        if (rowBytes is < 1 or > MaxRowBytes)
            throw new PdfInspectionException("geometria do predictor PNG inválida");

        int bytesPerPixel = Math.Max(1, (parameters.Colors * parameters.BitsPerComponent + 7) / 8);
        long stride = rowBytes + 1;
        if (data.Length == 0) return data;
        if (data.Length % stride != 0)
            throw new PdfInspectionException("dados do predictor PNG não casam com a geometria declarada");

        int rows = (int)(data.LongLength / stride);
        var output = new byte[rows * rowBytes];
        int width = (int)rowBytes;

        for (int row = 0; row < rows; row++)
        {
            int source = (int)(row * stride);
            byte filter = data[source];
            int current = row * width;
            int previous = current - width; // < 0 na 1ª linha: tudo zero

            for (int index = 0; index < width; index++)
            {
                byte raw = data[source + 1 + index];
                int left = index >= bytesPerPixel ? output[current + index - bytesPerPixel] : 0;
                int up = previous >= 0 ? output[previous + index] : 0;
                int upLeft = previous >= 0 && index >= bytesPerPixel
                    ? output[previous + index - bytesPerPixel]
                    : 0;

                output[current + index] = filter switch
                {
                    0 => raw,
                    1 => (byte)(raw + left),
                    2 => (byte)(raw + up),
                    3 => (byte)(raw + ((left + up) >> 1)),
                    4 => (byte)(raw + Paeth(left, up, upLeft)),
                    _ => throw new PdfInspectionException(
                        $"tipo de filtro de linha PNG inválido ({filter})"),
                };
            }
        }

        return output;
    }

    private static int Paeth(int a, int b, int c)
    {
        int p = a + b - c;
        int pa = Math.Abs(p - a);
        int pb = Math.Abs(p - b);
        int pc = Math.Abs(p - c);
        if (pa <= pb && pa <= pc) return a;
        return pb <= pc ? b : c;
    }

    private static int ReadOptionalInt(DictionaryToken parameters, string key, int fallback) =>
        parameters.TryGet(NameToken.Create(key), out IToken? token) ? ReadInt(token, "/" + key) : fallback;

    private static int ReadInt(IToken token, string name)
    {
        if (token is NumericToken { Double: var value } && value == Math.Floor(value)
            && value is >= 0 and <= int.MaxValue)
            return (int)value;

        throw new PdfInspectionException($"valor de {name} em /DecodeParms não suportado");
    }
}
