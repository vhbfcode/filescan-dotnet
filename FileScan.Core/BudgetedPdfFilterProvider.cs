using System.IO.Compression;
using UglyToad.PdfPig.Filters;
using UglyToad.PdfPig.Tokens;

namespace FileScan.Scanning;

/// <summary>
/// Restringe o PdfPig ao subconjunto que o FileScan consegue limitar de forma observável.
/// Aceita FlateDecode (teto por stream + agregado, com predictor PNG), ASCII85Decode e ASCIIHexDecode,
/// sozinhos ou encadeados (até <see cref="MaxChainLength"/> filtros; cada etapa é cobrada no
/// orçamento). Predictor TIFF, LZW, RunLength e codecs de imagem falham fechados quando precisam ser
/// decodificados (streams /Subtype /Image que não são anexo nem chegam a ser decodificados).
/// </summary>
internal sealed class BudgetedPdfFilterProvider(ScanBudget budget) : IFilterProvider
{
    /// <summary>Teto de filtros por stream. Cadeias reais têm 1 ou 2; mais que isso é suspeito.</summary>
    internal const int MaxChainLength = 4;

    private static readonly IFilterProvider Inner = DefaultFilterProvider.Instance;

    public IReadOnlyList<IFilter> GetFilters(DictionaryToken streamDictionary) =>
        Wrap(Inner.GetFilters(streamDictionary));

    public IReadOnlyList<IFilter> GetNamedFilters(IReadOnlyList<NameToken> names) =>
        Wrap(Inner.GetNamedFilters(names));

    public IReadOnlyList<IFilter> GetAllFilters() => Wrap(Inner.GetAllFilters(), allowMany: true);

    private IReadOnlyList<IFilter> Wrap(IReadOnlyList<IFilter> filters, bool allowMany = false)
    {
        if (filters.Count == 0) return [];

        if (!allowMany && filters.Count > MaxChainLength)
            return [new UnsupportedPdfFilter(
                $"cadeia de filtros PDF com mais de {MaxChainLength} filtros não suportada")];

        return filters.Select(WrapOne).ToArray();
    }

    private IFilter WrapOne(IFilter filter)
    {
        string type = filter.GetType().Name;
        if (filter.IsSupported)
        {
            if (type.Contains("Flate", StringComparison.OrdinalIgnoreCase))
                return new BudgetedFlateFilter(budget);
            if (type.Contains("Ascii85", StringComparison.OrdinalIgnoreCase))
                return new BudgetedAsciiFilter(budget, filter, ascii85: true);
            if (type.Contains("AsciiHex", StringComparison.OrdinalIgnoreCase))
                return new BudgetedAsciiFilter(budget, filter, ascii85: false);
        }

        return new UnsupportedPdfFilter($"filtro PDF não suportado: {type}");
    }

    private sealed class BudgetedFlateFilter(ScanBudget budget) : IFilter
    {
        public bool IsSupported => true;

        public Memory<byte> Decode(Memory<byte> input, DictionaryToken streamDictionary,
            IFilterProvider filterProvider, int filterIndex)
        {
            // Valida os parâmetros ANTES de inflar: predictor não suportado falha sem gastar orçamento.
            var predictor = PdfPredictor.Read(streamDictionary, filterIndex);

            try
            {
                using var source = new MemoryStream(input.ToArray(), writable: false);
                using var zlib = new ZLibStream(source, CompressionMode.Decompress);
                byte[] inflated = budget.ReadExpanded(zlib, "PDF /FlateDecode");
                return predictor is { } parameters ? PdfPredictor.ApplyPng(inflated, parameters) : inflated;
            }
            catch (ScanLimitExceededException)
            {
                throw;
            }
            catch (Exception ex) when (ex is InvalidDataException or IOException)
            {
                throw new PdfInspectionException("stream /FlateDecode inválido ou truncado", ex);
            }
        }
    }

    /// <summary>
    /// ASCII85/ASCIIHex só encolhem (exceto o atalho 'z' do ASCII85, 1 -> 4 bytes). O pior caso é
    /// verificado antes de decodificar e a saída real é cobrada no orçamento depois.
    /// </summary>
    private sealed class BudgetedAsciiFilter(ScanBudget budget, IFilter inner, bool ascii85) : IFilter
    {
        public bool IsSupported => true;

        public Memory<byte> Decode(Memory<byte> input, DictionaryToken streamDictionary,
            IFilterProvider filterProvider, int filterIndex)
        {
            if (PdfPredictor.Read(streamDictionary, filterIndex) is not null)
                throw new PdfInspectionException("predictor /DecodeParms em filtro ASCII não suportado");

            var span = input.Span;
            long worstCase = span.Length;
            if (ascii85)
            {
                long z = 0;
                foreach (byte value in span) if (value == (byte)'z') z++;
                worstCase += 3 * z; // cada 'z' ocupa 1 char e vira 4 bytes
            }
            budget.EnsureCanExpand(worstCase, ascii85 ? "PDF /ASCII85Decode" : "PDF /ASCIIHexDecode");

            Memory<byte> decoded;
            try
            {
                decoded = inner.Decode(input, streamDictionary, filterProvider, filterIndex);
            }
            catch (Exception ex) when (ex is not (ScanLimitExceededException or OperationCanceledException))
            {
                throw new PdfInspectionException(
                    ascii85 ? "stream /ASCII85Decode inválido" : "stream /ASCIIHexDecode inválido", ex);
            }

            budget.CopyExpanded(decoded, ascii85 ? "PDF /ASCII85Decode" : "PDF /ASCIIHexDecode");
            return decoded;
        }
    }

    private sealed class UnsupportedPdfFilter(string reason) : IFilter
    {
        public bool IsSupported => false;

        public Memory<byte> Decode(Memory<byte> input, DictionaryToken streamDictionary,
            IFilterProvider filterProvider, int filterIndex) =>
            throw new PdfInspectionException(reason);
    }
}
