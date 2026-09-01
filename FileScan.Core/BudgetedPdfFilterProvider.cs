using System.IO.Compression;
using UglyToad.PdfPig.Filters;
using UglyToad.PdfPig.Tokens;

namespace FileScan.Scanning;

/// <summary>
/// Restringe o PdfPig ao subconjunto que o FileScan consegue limitar de forma observável.
/// FlateDecode simples é lido com teto por stream + teto agregado; filtros encadeados, predictors
/// e codecs sem leitura limitada falham fechados.
/// </summary>
internal sealed class BudgetedPdfFilterProvider(ScanBudget budget) : IFilterProvider
{
    private static readonly IFilterProvider Inner = DefaultFilterProvider.Instance;

    public IReadOnlyList<IFilter> GetFilters(DictionaryToken streamDictionary) =>
        Wrap(Inner.GetFilters(streamDictionary));

    public IReadOnlyList<IFilter> GetNamedFilters(IReadOnlyList<NameToken> names) =>
        Wrap(Inner.GetNamedFilters(names));

    public IReadOnlyList<IFilter> GetAllFilters() => Wrap(Inner.GetAllFilters(), allowMany: true);

    private IReadOnlyList<IFilter> Wrap(IReadOnlyList<IFilter> filters, bool allowMany = false)
    {
        if (filters.Count == 0) return [];

        if (!allowMany && filters.Count != 1)
            return [new UnsupportedPdfFilter("cadeia de filtros PDF não suportada")];

        return filters.Select(WrapOne).ToArray();
    }

    private IFilter WrapOne(IFilter filter)
    {
        string type = filter.GetType().Name;
        return filter.IsSupported && type.Contains("Flate", StringComparison.OrdinalIgnoreCase)
            ? new BudgetedFlateFilter(budget)
            : new UnsupportedPdfFilter($"filtro PDF não suportado: {type}");
    }

    private sealed class BudgetedFlateFilter(ScanBudget budget) : IFilter
    {
        public bool IsSupported => true;

        public Memory<byte> Decode(Memory<byte> input, DictionaryToken streamDictionary,
            IFilterProvider filterProvider, int filterIndex)
        {
            EnsureNoUnsupportedPredictor(streamDictionary);

            try
            {
                using var source = new MemoryStream(input.ToArray(), writable: false);
                using var zlib = new ZLibStream(source, CompressionMode.Decompress);
                return budget.ReadExpanded(zlib, "PDF /FlateDecode");
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

        private static void EnsureNoUnsupportedPredictor(DictionaryToken dictionary)
        {
            if (!dictionary.TryGet(NameToken.DecodeParms, out IToken? decodeParms)
                || decodeParms is NullToken)
                return;

            if (decodeParms is DictionaryToken parameters)
            {
                if (!parameters.TryGet(NameToken.Predictor, out IToken? predictor)) return;
                if (predictor is NumericToken number && number.Double == 1) return;
            }

            throw new PdfInspectionException("predictor /DecodeParms não suportado");
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
