using System.Text;

namespace FileScan.Scanning;

/// <summary>
/// Scanner lexical pequeno usado somente sobre tokens/streams já delimitados pelo parser estrutural.
/// Nunca é usado como fallback capaz de produzir Clean: se o parser falhar, seus achados são apenas
/// defesa adicional e a inspeção continua incompleta.
/// </summary>
internal static class PdfNameScanner
{
    public static bool Scan(ReadOnlySpan<byte> data, List<string> findings, HashSet<string> seen)
    {
        bool complete = true;

        for (int i = 0; i < data.Length; i++)
        {
            byte current = data[i];

            if (current == (byte)'%')
            {
                while (i < data.Length && data[i] is not ((byte)'\r') and not ((byte)'\n')) i++;
                continue;
            }

            if (current == (byte)'(')
            {
                int depth = 1;
                bool escaped = false;
                while (++i < data.Length)
                {
                    byte value = data[i];
                    if (escaped) { escaped = false; continue; }
                    if (value == (byte)'\\') { escaped = true; continue; }
                    if (value == (byte)'(') depth++;
                    else if (value == (byte)')' && --depth == 0) break;
                }

                if (depth != 0) complete = false;
                continue;
            }

            if (current == (byte)'<' && i + 1 < data.Length && data[i + 1] == (byte)'<')
            {
                i++; // operador de dicionário; não tratar o segundo '<' como hex string
                continue;
            }

            if (current == (byte)'<')
            {
                while (++i < data.Length && data[i] != (byte)'>') { }
                if (i >= data.Length) complete = false;
                continue;
            }

            if (current != (byte)'/') continue;

            int start = ++i;
            while (i < data.Length && !IsDelimiter(data[i])) i++;
            AddName(data[start..i], findings, seen);
            i--;
        }

        return complete;
    }

    public static void AddName(string name, List<string> findings, HashSet<string> seen)
    {
        if (name.Contains('#', StringComparison.Ordinal))
            name = NormalizeName(name);

        string label = name switch
        {
            "JavaScript" => "JavaScript (/JavaScript)",
            "JS" => "JavaScript (/JS)",
            "Launch" => "execução de programa externo (/Launch)",
            _ => string.Empty,
        };

        if (label.Length > 0 && seen.Add(label)) findings.Add(label);
    }

    private static string NormalizeName(string raw)
    {
        Span<char> normalized = raw.Length <= 256 ? stackalloc char[raw.Length] : new char[raw.Length];
        int written = 0;
        for (int i = 0; i < raw.Length; i++)
        {
            if (raw[i] == '#' && i + 2 < raw.Length
                && IsHex((byte)raw[i + 1]) && IsHex((byte)raw[i + 2]))
            {
                normalized[written++] = (char)((Hex((byte)raw[i + 1]) << 4) | Hex((byte)raw[i + 2]));
                i += 2;
            }
            else
            {
                normalized[written++] = raw[i];
            }
        }
        return new string(normalized[..written]);
    }

    private static void AddName(ReadOnlySpan<byte> raw, List<string> findings, HashSet<string> seen)
    {
        if (raw.IsEmpty) return;

        Span<byte> normalized = raw.Length <= 256 ? stackalloc byte[raw.Length] : new byte[raw.Length];
        int written = 0;
        for (int i = 0; i < raw.Length; i++)
        {
            if (raw[i] == (byte)'#' && i + 2 < raw.Length
                && IsHex(raw[i + 1]) && IsHex(raw[i + 2]))
            {
                normalized[written++] = (byte)((Hex(raw[i + 1]) << 4) | Hex(raw[i + 2]));
                i += 2;
            }
            else
            {
                normalized[written++] = raw[i];
            }
        }

        AddName(Encoding.ASCII.GetString(normalized[..written]), findings, seen);
    }

    private static bool IsDelimiter(byte value) =>
        value is (byte)' ' or (byte)'\t' or (byte)'\r' or (byte)'\n' or 0x0C or 0x00
            or (byte)'(' or (byte)')' or (byte)'<' or (byte)'>' or (byte)'[' or (byte)']'
            or (byte)'{' or (byte)'}' or (byte)'/' or (byte)'%';

    private static bool IsHex(byte value) =>
        value is >= (byte)'0' and <= (byte)'9'
            or >= (byte)'a' and <= (byte)'f'
            or >= (byte)'A' and <= (byte)'F';

    private static int Hex(byte value) => value >= (byte)'a' ? value - (byte)'a' + 10
        : value >= (byte)'A' ? value - (byte)'A' + 10
        : value - (byte)'0';
}
