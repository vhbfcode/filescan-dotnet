namespace FileScan.Scanning;

/// <summary>Resumo estrutural de um objeto, calculado pela guarda pré-Open com os tokenizadores do PdfPig.</summary>
internal sealed class PdfObjectSummary
{
    public int AliasTo = -1;

    /// <summary>Referências alcançadas por /Kids (descendo em dicionários DIRETOS), com peso = níveis de aninhamento.</summary>
    public List<(int Target, int Weight)> KidsEdges = [];

    /// <summary>/Kids n 0 R: o array de filhos vive em outro objeto (que passa a ser aresta e nó).</summary>
    public List<(int Holder, int Weight)> KidsHolders = [];

    /// <summary>Se o objeto É um array: o que ele contém visto como valor de /Kids.</summary>
    public List<(int Target, int Weight)>? ArrayEdges;

    public List<(int Holder, int Weight)> ArrayHolders = [];

    /// <summary>TODA referência indireta do valor (dicionário/array, recursivamente).</summary>
    public int[] References = [];

    /// <summary>Alguma referência indireta com geração diferente de 0 (o PdfPig procura por número E geração).</summary>
    public bool NonZeroGenerationReference;
}

/// <summary>Objeto indireto de nível superior (<c>n g obj ... endobj</c>) achado na varredura de cobertura.</summary>
internal sealed class PdfTopLevelObject
{
    public long Start;
    public long End;
    public bool HasStream;
    public bool IsXRefStream;
    public int Number;
    public int Generation;
    /// <summary>Intervalo do valor do corpo (para um stream, o dicionário).</summary>
    public int BodyStart;
    public int BodyEnd;
    public int DataStart = -1;
    public int DataEnd = -1;
    public PdfObjectSummary Summary = new();
}

/// <summary>
/// Cobertura de bytes do arquivo PDF. Todo byte que não seja whitespace nem comentário, do cabeçalho
/// ao fim, precisa pertencer a (a) um objeto indireto <c>n g obj ... endobj</c>, (b) uma seção
/// <c>xref</c> + <c>trailer</c> ou (c) uma linha <c>startxref &lt;n&gt;</c> (o <c>%%EOF</c> é comentário).
/// Qualquer lacuna — texto/HTML/binário solto entre objetos, antes de um <c>startxref</c> falso, ou
/// um "linearizado" com lixo no meio — é devolvida em <c>GapOffset</c>, e o PDF vira <c>NotInspected</c>.
/// Não depende de xref nem de offsets: percorre a gramática de nível superior de ponta a ponta (custo
/// linear; o corpo de streams é saltado por /Length ou por <c>endstream</c>).
/// Este scanner só DELIMITA objetos; quem interpreta chaves, nomes e referências é a guarda pré-Open,
/// com os tokenizadores do próprio PdfPig (mesma normalização de <c>#xx</c>, comentários e referências).
/// </summary>
internal static class PdfByteCoverage
{
    private const int MaxNesting = 64;

    internal sealed record Result(
        IReadOnlyList<PdfTopLevelObject> Objects,
        long? GapOffset,
        IReadOnlyList<(int Start, int End)> Trailers,
        IReadOnlyList<long> XrefSectionStarts,
        IReadOnlyList<(long Offset, int Number)> XrefEntries,
        long? LastStartxref,
        IReadOnlyDictionary<long, HashSet<int>> XrefInUseBySection,
        bool XrefNonZeroGeneration);

    public static Result Scan(byte[] data, ScanBudget budget)
    {
        var objects = new List<PdfTopLevelObject>();
        var trailers = new List<(int, int)>();
        var sections = new List<long>();
        var entries = new List<(long, int)>();
        var inUseBySection = new Dictionary<long, HashSet<int>>();
        long? lastStartxref = null;
        var scanner = new Scanner(data);
        int position = 0;

        Result Done(long? gap) => new(objects, gap, trailers, sections, entries, lastStartxref, inUseBySection, scanner.NonZeroGeneration);

        while (true)
        {
            budget.ThrowIfCancellationRequested();
            scanner.Position = position;
            scanner.SkipWhitespaceAndComments();
            position = scanner.Position;
            if (position >= data.Length) return Done(null);

            int start = position;
            if (scanner.IsKeyword("xref"))
            {
                sections.Add(start);
                scanner.Position += 4;
                var sectionInUse = new HashSet<int>();
                inUseBySection[start] = sectionInUse;
                if (!scanner.SkipXrefTable(entries, sectionInUse)) return Done(start);
            }
            else if (scanner.IsKeyword("trailer"))
            {
                scanner.Position += 7;
                scanner.SkipWhitespaceAndComments();
                int dictionaryStart = scanner.Position;
                if (!scanner.ParseValue(0, out _)) return Done(start);
                trailers.Add((dictionaryStart, scanner.Position));
            }
            else if (scanner.IsKeyword("startxref"))
            {
                scanner.Position += 9;
                scanner.SkipWhitespaceAndComments();
                if (!scanner.TryReadInteger(out long offset)) return Done(start);
                lastStartxref = offset;
            }
            else if (position < data.Length && data[position] is >= (byte)'0' and <= (byte)'9')
            {
                if (!scanner.TryParseObject(start, out PdfTopLevelObject? item)) return Done(start);
                objects.Add(item!);
            }
            else
            {
                return Done(start);
            }

            position = scanner.Position;
        }
    }

    private sealed class DictionaryInfo
    {
        public long? Length;
    }

    private sealed class Scanner(byte[] data)
    {
        public int Position;

        public void SkipWhitespaceAndComments()
        {
            while (Position < data.Length)
            {
                byte value = data[Position];
                if (IsWhitespace(value))
                {
                    Position++;
                }
                else if (value == (byte)'%')
                {
                    while (Position < data.Length && data[Position] is not ((byte)'\r' or (byte)'\n')) Position++;
                }
                else
                {
                    break;
                }
            }
        }

        private void SkipWhitespace()
        {
            while (Position < data.Length && IsWhitespace(data[Position])) Position++;
        }

        public bool IsKeyword(string keyword)
        {
            int end = Position + keyword.Length;
            if (end > data.Length) return false;
            for (int i = 0; i < keyword.Length; i++)
                if (data[Position + i] != (byte)keyword[i]) return false;
            return end == data.Length || !IsRegular(data[end]);
        }

        public bool TryReadInteger(out long value)
        {
            value = 0;
            int start = Position;
            while (Position < data.Length && data[Position] is >= (byte)'0' and <= (byte)'9')
            {
                if (Position - start > 18) return false;
                value = value * 10 + (data[Position] - (byte)'0');
                Position++;
            }
            return Position > start && (Position >= data.Length || !IsRegular(data[Position]));
        }

        /// <summary>Alguma entrada 'n' de tabela xref com geração diferente de 0.</summary>
        public bool NonZeroGeneration;

        public bool SkipXrefTable(List<(long, int)> entries, HashSet<int> inUse)
        {
            while (true)
            {
                SkipWhitespaceAndComments();
                if (IsKeyword("trailer")) return true; // o laço principal consome o trailer
                if (!TryReadInteger(out long firstNumber)) return false;
                SkipWhitespace();
                if (!TryReadInteger(out long count)) return false;
                if (count > (data.Length - Position) / 10 + 1) return false;

                for (long i = 0; i < count; i++)
                {
                    SkipWhitespace();
                    if (!TryReadInteger(out long offset)) return false;
                    SkipWhitespace();
                    if (!TryReadInteger(out long entryGeneration)) return false;
                    SkipWhitespace();
                    if (Position >= data.Length || data[Position] is not ((byte)'n' or (byte)'f')) return false;
                    if (data[Position] == (byte)'n')
                    {
                        if (entryGeneration != 0) NonZeroGeneration = true;
                        if (firstNumber + i <= int.MaxValue)
                        {
                            if (offset > 0) entries.Add((offset, (int)(firstNumber + i)));
                            inUse.Add((int)(firstNumber + i));
                        }
                        else if (offset > 0) entries.Add((offset, -1));
                    }
                    Position++;
                    if (Position < data.Length && IsRegular(data[Position])) return false;
                }
            }
        }

        public bool TryParseObject(int objectStart, out PdfTopLevelObject? item)
        {
            item = null;
            if (!TryReadInteger(out long number) || number > int.MaxValue) return false;
            SkipWhitespace();
            if (!TryReadInteger(out long generation) || generation > int.MaxValue) return false;
            SkipWhitespace();
            if (!IsKeyword("obj")) return false;
            Position += 3;

            SkipWhitespaceAndComments();
            int bodyStart = Position;
            if (!ParseValue(0, out DictionaryInfo? info)) return false;
            int bodyEnd = Position;
            SkipWhitespaceAndComments();

            var result = new PdfTopLevelObject
            {
                Start = objectStart,
                Number = (int)number,
                Generation = (int)generation,
                BodyStart = bodyStart,
                BodyEnd = bodyEnd,
            };

            if (IsKeyword("stream"))
            {
                if (info is null) return false;
                result.HasStream = true;
                Position += 6;
                while (Position < data.Length && data[Position] is (byte)' ' or (byte)'\t') Position++;
                if (Position < data.Length && data[Position] == (byte)'\r') Position++;
                if (Position < data.Length && data[Position] == (byte)'\n') Position++;
                else if (data[Position - 1] != (byte)'\r') return false;

                int dataStart = Position;
                result.DataStart = dataStart;
                bool resolved = false;
                if (info.Length is { } length && length >= 0 && dataStart + length <= data.Length)
                {
                    Position = (int)(dataStart + length);
                    SkipWhitespace();
                    if (IsKeyword("endstream"))
                    {
                        result.DataEnd = (int)(dataStart + length);
                        Position += 9;
                        resolved = true;
                    }
                }

                if (!resolved)
                {
                    int index = data.AsSpan(dataStart).IndexOf("endstream"u8);
                    if (index < 0) return false;
                    result.DataEnd = dataStart + index;
                    Position = dataStart + index + 9;
                }

                SkipWhitespaceAndComments();
            }

            if (!IsKeyword("endobj")) return false;
            Position += 6;
            result.End = Position;
            item = result;
            return true;
        }

        public bool ParseValue(int depth, out DictionaryInfo? dictionaryInfo)
        {
            dictionaryInfo = null;
            if (depth > MaxNesting || Position >= data.Length) return false;

            byte value = data[Position];
            switch (value)
            {
                case (byte)'<':
                    if (Position + 1 < data.Length && data[Position + 1] == (byte)'<')
                    {
                        Position += 2;
                        dictionaryInfo = new DictionaryInfo();
                        return ParseDictionaryBody(depth, dictionaryInfo);
                    }
                    return SkipHexString();

                case (byte)'[':
                    Position++;
                    while (true)
                    {
                        SkipWhitespaceAndComments();
                        if (Position >= data.Length) return false;
                        if (data[Position] == (byte)']')
                        {
                            Position++;
                            return true;
                        }
                        if (!ParseValue(depth + 1, out _)) return false;
                    }

                case (byte)'(':
                    return SkipLiteralString();

                case (byte)'/':
                    Position++;
                    while (Position < data.Length && IsRegular(data[Position])) Position++;
                    return true;

                default:
                    return ParseBareToken();
            }
        }

        private bool ParseDictionaryBody(int depth, DictionaryInfo info)
        {
            while (true)
            {
                SkipWhitespaceAndComments();
                if (Position + 1 >= data.Length) return false;
                if (data[Position] == (byte)'>' && data[Position + 1] == (byte)'>')
                {
                    Position += 2;
                    return true;
                }
                if (data[Position] != (byte)'/') return false;

                int keyStart = ++Position;
                while (Position < data.Length && IsRegular(data[Position])) Position++;
                string key = System.Text.Encoding.Latin1.GetString(data, keyStart, Position - keyStart);

                SkipWhitespaceAndComments();
                int valueStart = Position;
                if (!ParseValue(depth + 1, out _)) return false;

                // Só ajuda a saltar o corpo do stream; se a chave vier escapada (/Len#67th) cai no
                // fallback por "endstream". Quem interpreta chaves é a guarda, com o tokenizador do PdfPig.
                if (depth == 0 && key == "Length" && TryParseDigits(valueStart, Position, out long length))
                    info.Length = length;
            }
        }

        private bool TryParseDigits(int start, int end, out long value)
        {
            value = 0;
            if (end <= start || end - start > 18) return false;
            for (int i = start; i < end; i++)
            {
                if (data[i] is < (byte)'0' or > (byte)'9') return false;
                value = value * 10 + (data[i] - (byte)'0');
            }
            return true;
        }

        private bool SkipHexString()
        {
            Position++;
            while (Position < data.Length)
            {
                byte value = data[Position++];
                if (value == (byte)'>') return true;
                bool hex = value is >= (byte)'0' and <= (byte)'9' or >= (byte)'a' and <= (byte)'f'
                    or >= (byte)'A' and <= (byte)'F';
                if (!hex && !IsWhitespace(value)) return false;
            }
            return false;
        }

        private bool SkipLiteralString()
        {
            int depth = 0;
            while (Position < data.Length)
            {
                byte value = data[Position++];
                if (value == (byte)'\\')
                {
                    Position++;
                }
                else if (value == (byte)'(')
                {
                    depth++;
                }
                else if (value == (byte)')' && --depth == 0)
                {
                    return true;
                }
            }
            return false;
        }

        // número (inclusive "n g R"), true, false ou null; qualquer outra palavra é lacuna.
        private bool ParseBareToken()
        {
            int start = Position;
            while (Position < data.Length && IsRegular(data[Position])) Position++;
            int length = Position - start;
            if (length == 0) return false;

            var token = data.AsSpan(start, length);
            if (token.SequenceEqual("true"u8) || token.SequenceEqual("false"u8) || token.SequenceEqual("null"u8))
                return true;

            foreach (byte value in token)
                if (value is not (>= (byte)'0' and <= (byte)'9') and not (byte)'+' and not (byte)'-' and not (byte)'.')
                    return false;

            // referência indireta "n g R"?
            bool unsigned = true;
            foreach (byte value in token) unsigned &= value is >= (byte)'0' and <= (byte)'9';
            if (unsigned)
            {
                int saved = Position;
                SkipWhitespace();
                int generationStart = Position;
                while (Position < data.Length && data[Position] is >= (byte)'0' and <= (byte)'9') Position++;
                if (Position > generationStart)
                {
                    SkipWhitespace();
                    if (Position < data.Length && data[Position] == (byte)'R'
                        && (Position + 1 >= data.Length || !IsRegular(data[Position + 1])))
                    {
                        Position++;
                        return true;
                    }
                }
                Position = saved;
            }

            return true;
        }
    }

    private static bool IsWhitespace(byte value) =>
        value is (byte)' ' or (byte)'\t' or (byte)'\r' or (byte)'\n' or 0x0C or 0x00;

    private static bool IsDelimiter(byte value) =>
        value is (byte)'(' or (byte)')' or (byte)'<' or (byte)'>' or (byte)'[' or (byte)']'
            or (byte)'{' or (byte)'}' or (byte)'/' or (byte)'%';

    private static bool IsRegular(byte value) => !IsWhitespace(value) && !IsDelimiter(value);
}
