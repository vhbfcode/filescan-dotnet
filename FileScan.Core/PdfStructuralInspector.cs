using System.Security.Cryptography;
using UglyToad.PdfPig;
using UglyToad.PdfPig.Core;
using UglyToad.PdfPig.Tokens;

namespace FileScan.Scanning;

internal sealed record PdfStructuralInspection(
    IReadOnlyList<string> Findings,
    IReadOnlyList<string> Incomplete,
    IReadOnlyList<byte[]> EmbeddedFiles);

/// <summary>
/// Fronteira PDF estrutural. O PdfPig valida xref/trailer, referências, updates e object streams;
/// o FileScan limita filtros/recursos, percorre os tokens e propaga qualquer ambiguidade como
/// incompletude. Não existe caminho textual alternativo capaz de concluir Clean.
/// </summary>
internal static class PdfStructuralInspector
{
    private const int MaxTokenNesting = 64;
    private static readonly NameToken EfKey = NameToken.Create("EF");
    private static readonly NameToken EmbeddedFilesKey = NameToken.Create("EmbeddedFiles");
    private static readonly NameToken AssociatedFilesKey = NameToken.Create("AF");
    private static readonly NameToken FileSpecificationKey = NameToken.Create("FS");
    private static readonly NameToken NamesKey = NameToken.Create("Names");
    private static readonly NameToken KidsKey = NameToken.Create("Kids");
    private static readonly NameToken LimitsKey = NameToken.Create("Limits");
    private static readonly NameToken FileAttachmentName = NameToken.Create("FileAttachment");

    private sealed record NameTreeRange(byte[] First, byte[] Last);

    private enum FileSpecContext
    {
        TypedDictionary,
        EmbeddedFilesNameTree,
        AssociatedFilesArray,
        FileAttachment,
    }

    public static PdfStructuralInspection Inspect(byte[] content, ScanBudget budget)
    {
        budget.ThrowIfCancellationRequested();
        var findings = new List<string>();
        var findingsSeen = new HashSet<string>(StringComparer.Ordinal);
        var incomplete = new List<string>();
        var incompleteSeen = new HashSet<string>(StringComparer.Ordinal);
        var embedded = new List<byte[]>();
        var embeddedHashes = new HashSet<string>(StringComparer.Ordinal);

        if (!HasStrictFinalEof(content))
        {
            AddOnce(incomplete, incompleteSeen,
                "estrutura inválida: %%EOF final ausente ou seguido de bytes não-whitespace");
            PdfNameScanner.Scan(content, findings, findingsSeen);
            budget.ThrowIfCancellationRequested();
            return new(findings, incomplete, embedded);
        }

        var filterProvider = new BudgetedPdfFilterProvider(budget);
        var options = new ParsingOptions
        {
            UseLenientParsing = false,
            MaxStackDepth = MaxTokenNesting,
            FilterProvider = filterProvider,
        };

        PdfDocument document;
        try
        {
            document = PdfDocument.Open(content, options);
        }
        catch (Exception ex)
        {
            AddOnce(incomplete, incompleteSeen,
                $"estrutura PDF inválida, truncada ou não suportada ({ex.GetType().Name})");

            // Defesa adicional somente quando nem a fronteira estrutural pôde ser aberta. Como a
            // falha permanece em Incomplete, esta varredura jamais pode produzir Clean.
            PdfNameScanner.Scan(content, findings, findingsSeen);
            budget.ThrowIfCancellationRequested();
            return new(findings, incomplete, embedded);
        }

        budget.ThrowIfCancellationRequested();

        using (document)
        {
            budget.ThrowIfCancellationRequested();
            if (document.IsEncrypted)
            {
                AddOnce(incomplete, incompleteSeen,
                    "PDF criptografado: conteúdo não inspecionável sem credencial");
                return new(findings, incomplete, embedded);
            }

            try
            {
                var objects = new List<(IndirectReference Reference, ObjectToken Object)>();
                foreach (var reference in document.Structure.CrossReferenceTable.ObjectOffsets.Keys)
                {
                    budget.ConsumeEntry("objeto PDF");
                    objects.Add((reference, document.Structure.GetObject(reference)));
                }

                // /Type é opcional num embedded-file stream. Primeiro parte de associações
                // FileSpec normativas (/EmbeddedFiles, /AF, /FS de FileAttachment ou
                // /Type /Filespec) e resolve seus /EF; chaves /EF ou /FS desconhecidas em outro
                // dicionário não criam um anexo.
                // Só depois percorre os streams, tornando o resultado independente da ordem.
                var embeddedReferences = new HashSet<IndirectReference>();
                var embeddedDirectStreams = new HashSet<StreamToken>(ReferenceEqualityComparer.Instance);

                // /EmbeddedFiles só é a name tree de anexos quando está no /Names do catálogo
                // raiz. Uma chave homônima em dicionário de extensão não tem essa semântica.
                CollectFromCatalogNames(document.Structure.Catalog.CatalogDictionary, document,
                    embeddedReferences, embeddedDirectStreams, budget);

                foreach (var item in objects)
                {
                    budget.ThrowIfCancellationRequested();
                    CollectEmbeddedFileStreams(item.Object.Data, 0, document,
                        embeddedReferences, embeddedDirectStreams, budget);
                }

                foreach (var item in objects)
                {
                    budget.ThrowIfCancellationRequested();
                    WalkToken(item.Object.Data, 0, item.Reference, document, filterProvider, budget,
                        findings, findingsSeen, incomplete, incompleteSeen, embedded, embeddedHashes,
                        embeddedReferences, embeddedDirectStreams);
                    budget.ThrowIfCancellationRequested();
                }
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (ScanLimitExceededException ex)
            {
                AddOnce(incomplete, incompleteSeen, ex.Message);
            }
            catch (PdfInspectionException ex)
            {
                AddOnce(incomplete, incompleteSeen, ex.Message);
            }
            catch (Exception ex)
            {
                AddOnce(incomplete, incompleteSeen,
                    $"objeto/stream PDF inválido, truncado ou não suportado ({ex.GetType().Name})");
            }
        }

        budget.ThrowIfCancellationRequested();
        return new(findings, incomplete, embedded);
    }

    private static void WalkToken(IToken token, int nesting, IndirectReference containingReference,
        PdfDocument document,
        BudgetedPdfFilterProvider filterProvider, ScanBudget budget,
        List<string> findings, HashSet<string> findingsSeen,
        List<string> incomplete, HashSet<string> incompleteSeen,
        List<byte[]> embedded, HashSet<string> embeddedHashes,
        HashSet<IndirectReference> embeddedReferences,
        HashSet<StreamToken> embeddedDirectStreams)
    {
        budget.ThrowIfCancellationRequested();
        if (nesting > MaxTokenNesting)
            throw new PdfInspectionException($"aninhamento de tokens PDF excede {MaxTokenNesting}");

        switch (token)
        {
            case NameToken name:
                PdfNameScanner.AddName(name.Data, findings, findingsSeen);
                break;

            case DictionaryToken dictionary:
                foreach (var pair in dictionary.Data)
                {
                    PdfNameScanner.AddName(pair.Key, findings, findingsSeen);
                    WalkToken(pair.Value, nesting + 1, containingReference, document, filterProvider, budget,
                        findings, findingsSeen, incomplete, incompleteSeen, embedded, embeddedHashes,
                        embeddedReferences, embeddedDirectStreams);
                }
                break;

            case ArrayToken array:
                foreach (var item in array.Data)
                    WalkToken(item, nesting + 1, containingReference, document, filterProvider, budget,
                        findings, findingsSeen, incomplete, incompleteSeen, embedded, embeddedHashes,
                        embeddedReferences, embeddedDirectStreams);
                break;

            case StreamToken stream:
                WalkToken(stream.StreamDictionary, nesting + 1, containingReference, document, filterProvider, budget,
                    findings, findingsSeen, incomplete, incompleteSeen, embedded, embeddedHashes,
                    embeddedReferences, embeddedDirectStreams);
                ProcessStream(stream, containingReference, filterProvider, budget,
                    findings, findingsSeen,
                    incomplete, incompleteSeen, embedded, embeddedHashes,
                    embeddedReferences, embeddedDirectStreams);
                break;

            case ObjectToken nestedObject:
                WalkToken(nestedObject.Data, nesting + 1, containingReference, document, filterProvider, budget,
                    findings, findingsSeen, incomplete, incompleteSeen, embedded, embeddedHashes,
                    embeddedReferences, embeddedDirectStreams);
                break;
        }
    }

    private static void ProcessStream(StreamToken stream, IndirectReference containingReference,
        BudgetedPdfFilterProvider filterProvider,
        ScanBudget budget, List<string> findings, HashSet<string> findingsSeen,
        List<string> incomplete, HashSet<string> incompleteSeen,
        List<byte[]> embedded, HashSet<string> embeddedHashes,
        HashSet<IndirectReference> embeddedReferences,
        HashSet<StreamToken> embeddedDirectStreams)
    {
        budget.ConsumeEntry("stream PDF");
        byte[] decoded = Decode(stream, filterProvider, budget);
        string? type = GetName(stream.StreamDictionary, NameToken.Type);
        string? subtype = GetName(stream.StreamDictionary, NameToken.Subtype);

        if (string.Equals(type, "EmbeddedFile", StringComparison.Ordinal)
            || embeddedReferences.Contains(containingReference)
            || embeddedDirectStreams.Contains(stream))
        {
            budget.ConsumeEmbeddedFile();
            string hash = Convert.ToHexString(SHA256.HashData(decoded));
            if (embeddedHashes.Add(hash)) embedded.Add(decoded);
            return;
        }

        // Imagens/fontes/xref/metadata são dados, não sintaxe de ação PDF. Object streams e
        // content streams sem tipo são lexicalizados depois que o parser delimitou/decodificou o corpo.
        if (string.Equals(type, "XRef", StringComparison.Ordinal)
            || string.Equals(type, "Metadata", StringComparison.Ordinal)
            || string.Equals(type, "Font", StringComparison.Ordinal)
            || string.Equals(subtype, "Image", StringComparison.Ordinal))
            return;

        if (!PdfNameScanner.Scan(decoded, findings, findingsSeen))
            AddOnce(incomplete, incompleteSeen,
                "stream PDF contém string literal ou hexadecimal não terminada");
    }

    private static void CollectEmbeddedFileStreams(IToken token, int nesting, PdfDocument document,
        HashSet<IndirectReference> embeddedReferences,
        HashSet<StreamToken> embeddedDirectStreams,
        ScanBudget budget)
    {
        budget.ThrowIfCancellationRequested();
        if (nesting > MaxTokenNesting)
            throw new PdfInspectionException($"aninhamento de tokens PDF excede {MaxTokenNesting}");

        switch (token)
        {
            case DictionaryToken dictionary:
                if (string.Equals(GetName(dictionary, NameToken.Type), "Filespec", StringComparison.Ordinal))
                    CollectFromFileSpec(dictionary, document, embeddedReferences,
                        embeddedDirectStreams, budget, FileSpecContext.TypedDictionary);

                bool isFileAttachment = string.Equals(
                    GetName(dictionary, NameToken.Subtype), FileAttachmentName.Data,
                    StringComparison.Ordinal);

                foreach (var pair in dictionary.Data)
                {
                    if (pair.Key.Equals(AssociatedFilesKey))
                        CollectFromAssociatedFiles(pair.Value, document, embeddedReferences,
                            embeddedDirectStreams, budget);
                    else if (isFileAttachment && pair.Key.Equals(FileSpecificationKey))
                        CollectFromFileSpec(pair.Value, document, embeddedReferences,
                            embeddedDirectStreams, budget, FileSpecContext.FileAttachment);

                    CollectEmbeddedFileStreams(pair.Value, nesting + 1, document,
                        embeddedReferences, embeddedDirectStreams, budget);
                }
                break;

            case ArrayToken array:
                foreach (var item in array.Data)
                    CollectEmbeddedFileStreams(item, nesting + 1, document,
                        embeddedReferences, embeddedDirectStreams, budget);
                break;

            case StreamToken stream:
                CollectEmbeddedFileStreams(stream.StreamDictionary, nesting + 1, document,
                    embeddedReferences, embeddedDirectStreams, budget);
                break;

            case ObjectToken nestedObject:
                CollectEmbeddedFileStreams(nestedObject.Data, nesting + 1, document,
                    embeddedReferences, embeddedDirectStreams, budget);
                break;
        }
    }

    private static void CollectFromCatalogNames(DictionaryToken catalog, PdfDocument document,
        HashSet<IndirectReference> embeddedReferences,
        HashSet<StreamToken> embeddedDirectStreams,
        ScanBudget budget)
    {
        if (!catalog.TryGet(NamesKey, out IToken? namesToken)) return;

        IToken resolvedNames = ResolveIndirect(namesToken, document, out _);
        if (resolvedNames is not DictionaryToken namesDictionary)
            throw new PdfInspectionException("/Names do catálogo não resolve para um dicionário");

        if (namesDictionary.TryGet(EmbeddedFilesKey, out IToken? embeddedFilesToken))
            CollectFromEmbeddedFilesNameTree(embeddedFilesToken, document, embeddedReferences,
                embeddedDirectStreams, budget, new HashSet<IndirectReference>(), isRoot: true);
    }

    private static NameTreeRange? CollectFromEmbeddedFilesNameTree(IToken token, PdfDocument document,
        HashSet<IndirectReference> embeddedReferences,
        HashSet<StreamToken> embeddedDirectStreams,
        ScanBudget budget,
        HashSet<IndirectReference> visitedNodes,
        bool isRoot)
    {
        IToken resolved = ResolveIndirect(token, document, out IndirectReference? reference);
        if (reference is { } value && !visitedNodes.Add(value))
            throw new PdfInspectionException("referência indireta cíclica na name tree /EmbeddedFiles");

        if (resolved is not DictionaryToken tree)
            throw new PdfInspectionException("/EmbeddedFiles não resolve para uma name tree");

        bool hasNames = tree.TryGet(NamesKey, out IToken? namesToken);
        bool hasKids = tree.TryGet(KidsKey, out IToken? kidsToken);
        if (hasNames && hasKids)
            throw new PdfInspectionException(
                "name tree /EmbeddedFiles não pode possuir /Names e /Kids no mesmo nó");

        NameTreeRange? range = null;
        if (hasNames)
        {
            IToken resolvedNames = ResolveIndirect(namesToken!, document, out _);
            if (resolvedNames is not ArrayToken names || names.Data.Count % 2 != 0)
                throw new PdfInspectionException("name tree /EmbeddedFiles possui /Names inválido");

            byte[]? first = null;
            byte[]? previous = null;
            for (int index = 0; index < names.Data.Count; index += 2)
            {
                budget.ThrowIfCancellationRequested();

                if (!TryGetPdfStringBytes(names.Data[index], out byte[] current))
                    throw new PdfInspectionException(
                        "name tree /EmbeddedFiles possui chave que não é string");

                if (previous is not null && CompareNameTreeKeys(previous, current) >= 0)
                    throw new PdfInspectionException(
                        "name tree /EmbeddedFiles possui chaves duplicadas ou fora de ordem");

                first ??= current;
                previous = current;
                CollectFromFileSpec(names.Data[index + 1], document, embeddedReferences,
                    embeddedDirectStreams, budget, FileSpecContext.EmbeddedFilesNameTree);
            }

            if (first is not null && previous is not null)
                range = new NameTreeRange(first, previous);
        }

        if (hasKids)
        {
            IToken resolvedKids = ResolveIndirect(kidsToken!, document, out _);
            if (resolvedKids is not ArrayToken kids || kids.Data.Count == 0)
                throw new PdfInspectionException("name tree /EmbeddedFiles possui /Kids inválido");

            NameTreeRange? previousChild = null;
            foreach (IToken child in kids.Data)
            {
                budget.ThrowIfCancellationRequested();

                // ISO 32000 define /Kids como array de referências indiretas para outros nós.
                // Aceitar um dicionário direto aqui cria uma árvore que nenhum leitor conforme
                // precisa interpretar e não pode terminar em Clean.
                if (child is not IndirectReferenceToken)
                    throw new PdfInspectionException(
                        "name tree /EmbeddedFiles possui filho direto em /Kids");

                NameTreeRange? childRange = CollectFromEmbeddedFilesNameTree(
                    child, document, embeddedReferences,
                    embeddedDirectStreams, budget, visitedNodes, isRoot: false);
                if (childRange is null)
                    throw new PdfInspectionException(
                        "name tree /EmbeddedFiles possui filho vazio em /Kids");

                if (previousChild is not null
                    && CompareNameTreeKeys(previousChild.Last, childRange.First) >= 0)
                    throw new PdfInspectionException(
                        "name tree /EmbeddedFiles possui intervalos de /Kids sobrepostos ou fora de ordem");

                range = range is null
                    ? childRange
                    : new NameTreeRange(range.First, childRange.Last);
                previousChild = childRange;
            }
        }

        if (!hasNames && !hasKids)
            throw new PdfInspectionException("name tree /EmbeddedFiles não possui /Names nem /Kids");

        ValidateNameTreeLimits(tree, range, document, isRoot);
        return range;
    }

    private static void ValidateNameTreeLimits(DictionaryToken tree, NameTreeRange? range,
        PdfDocument document, bool isRoot)
    {
        if (isRoot && tree.TryGet(LimitsKey, out _))
            throw new PdfInspectionException(
                "raiz da name tree /EmbeddedFiles não pode possuir /Limits");

        if (!tree.TryGet(LimitsKey, out IToken? limitsToken))
        {
            if (!isRoot)
                throw new PdfInspectionException(
                    "nó não-raiz da name tree /EmbeddedFiles não possui /Limits");
            return;
        }

        IToken resolvedLimits = ResolveIndirect(limitsToken, document, out _);
        if (range is null || resolvedLimits is not ArrayToken { Data.Count: 2 } limits
            || !TryGetPdfStringBytes(limits.Data[0], out byte[] first)
            || !TryGetPdfStringBytes(limits.Data[1], out byte[] last)
            || !first.AsSpan().SequenceEqual(range.First)
            || !last.AsSpan().SequenceEqual(range.Last))
        {
            throw new PdfInspectionException(
                "name tree /EmbeddedFiles possui /Limits incoerente");
        }
    }

    private static bool TryGetPdfStringBytes(IToken token, out byte[] bytes)
    {
        switch (token)
        {
            case StringToken literal:
                bytes = literal.GetBytes();
                return true;
            case HexToken hexadecimal:
                bytes = hexadecimal.Memory.ToArray();
                return true;
            default:
                bytes = [];
                return false;
        }
    }

    private static int CompareNameTreeKeys(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
    {
        int sharedLength = Math.Min(left.Length, right.Length);
        for (int index = 0; index < sharedLength; index++)
        {
            int comparison = left[index].CompareTo(right[index]);
            if (comparison != 0) return comparison;
        }
        return left.Length.CompareTo(right.Length);
    }

    private static void CollectFromAssociatedFiles(IToken token, PdfDocument document,
        HashSet<IndirectReference> embeddedReferences,
        HashSet<StreamToken> embeddedDirectStreams,
        ScanBudget budget)
    {
        IToken resolved = ResolveIndirect(token, document, out _);
        if (resolved is not ArrayToken files)
            throw new PdfInspectionException("/AF não resolve para um array de FileSpec");

        foreach (IToken file in files.Data)
        {
            budget.ThrowIfCancellationRequested();
            CollectFromFileSpec(file, document, embeddedReferences,
                embeddedDirectStreams, budget, FileSpecContext.AssociatedFilesArray);
        }
    }

    private static void CollectFromFileSpec(IToken token, PdfDocument document,
        HashSet<IndirectReference> embeddedReferences,
        HashSet<StreamToken> embeddedDirectStreams,
        ScanBudget budget,
        FileSpecContext context)
    {
        IToken resolved = ResolveIndirect(token, document, out _);
        if (resolved is not DictionaryToken fileSpec)
        {
            // Uma file specification também pode ser uma string de caminho sem conteúdo embutido.
            if (resolved is StringToken
                && context is FileSpecContext.EmbeddedFilesNameTree or FileSpecContext.FileAttachment)
                return;

            string source = context switch
            {
                FileSpecContext.EmbeddedFilesNameTree => "valor da name tree /EmbeddedFiles",
                FileSpecContext.AssociatedFilesArray => "entrada do array /AF",
                FileSpecContext.FileAttachment => "/FS de annotation /FileAttachment",
                _ => "associação tipada",
            };
            throw new PdfInspectionException($"{source} não resolve para FileSpec");
        }

        if (fileSpec.TryGet(EfKey, out IToken? efToken))
            CollectFromEfDictionary(efToken, document, embeddedReferences,
                embeddedDirectStreams, budget);
    }

    private static void CollectFromEfDictionary(IToken efToken, PdfDocument document,
        HashSet<IndirectReference> embeddedReferences,
        HashSet<StreamToken> embeddedDirectStreams,
        ScanBudget budget)
    {
        IToken resolvedEf = ResolveIndirect(efToken, document, out _);
        if (resolvedEf is not DictionaryToken efDictionary || efDictionary.Data.Count == 0)
            throw new PdfInspectionException("FileSpec /EF ausente, vazio ou não resolvido como dicionário");

        foreach (var pair in efDictionary.Data)
        {
            budget.ThrowIfCancellationRequested();
            IToken resolved = ResolveIndirect(pair.Value, document, out IndirectReference? reference);
            if (resolved is not StreamToken stream)
                throw new PdfInspectionException(
                    $"FileSpec /EF /{pair.Key} não resolve para um embedded-file stream");

            if (reference is { } value) embeddedReferences.Add(value);
            else embeddedDirectStreams.Add(stream);
        }
    }

    private static IToken ResolveIndirect(IToken token, PdfDocument document,
        out IndirectReference? resolvedReference)
    {
        resolvedReference = null;
        var seen = new HashSet<IndirectReference>();
        while (token is IndirectReferenceToken indirect)
        {
            if (!seen.Add(indirect.Data))
                throw new PdfInspectionException("referência indireta cíclica em FileSpec /EF");

            resolvedReference = indirect.Data;
            try
            {
                token = document.Structure.GetObject(indirect.Data).Data;
            }
            catch (Exception ex)
            {
                throw new PdfInspectionException(
                    $"referência indireta ausente ou ilegível em FileSpec /EF ({indirect.Data})", ex);
            }
        }
        return token;
    }

    private static byte[] Decode(StreamToken stream, BudgetedPdfFilterProvider filterProvider,
        ScanBudget budget)
    {
        IReadOnlyList<UglyToad.PdfPig.Filters.IFilter> filters =
            filterProvider.GetFilters(stream.StreamDictionary);

        if (filters.Count == 0)
            return budget.CopyExpanded(stream.Data, "stream PDF sem filtro");

        Memory<byte> current = stream.Data;
        for (int index = 0; index < filters.Count; index++)
        {
            if (!filters[index].IsSupported)
                throw new PdfInspectionException("filtro PDF desconhecido ou encadeado não suportado");
            current = filters[index].Decode(current, stream.StreamDictionary, filterProvider, index);
        }
        return current.ToArray();
    }

    private static string? GetName(DictionaryToken dictionary, NameToken key)
    {
        if (!dictionary.TryGet(key, out IToken? token)) return null;
        return token is NameToken name ? name.Data : null;
    }

    private static bool HasStrictFinalEof(ReadOnlySpan<byte> content)
    {
        int end = content.Length - 1;
        while (end >= 0 && IsWhitespace(content[end])) end--;
        ReadOnlySpan<byte> marker = "%%EOF"u8;
        return end + 1 >= marker.Length
            && content[(end + 1 - marker.Length)..(end + 1)].SequenceEqual(marker);
    }

    private static bool IsWhitespace(byte value) =>
        value is (byte)' ' or (byte)'\t' or (byte)'\r' or (byte)'\n' or 0x0C or 0x00;

    private static void AddOnce(List<string> list, HashSet<string> seen, string message)
    {
        if (seen.Add(message)) list.Add(message);
    }
}
