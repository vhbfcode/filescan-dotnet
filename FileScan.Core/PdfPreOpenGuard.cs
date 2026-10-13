using UglyToad.PdfPig.Core;
using UglyToad.PdfPig.Tokenization.Scanner;
using UglyToad.PdfPig.Tokens;

namespace FileScan.Scanning;

internal sealed record PdfGuardResult(string? Refusal, bool Encrypted);

/// <summary>
/// Guarda ANTES do <c>PdfDocument.Open</c> (PdfPig 0.1.16). O Open percorre, sem limite nem detecção
/// de ciclo, estruturas recursivas controladas pelo arquivo — e um estouro de pilha NÃO é capturável,
/// derruba o processo hospedeiro (DoS por upload). Levantamento no código da tag v0.1.16:
/// <list type="number">
/// <item><c>NameTreeParser.FlattenNameTree</c> (catálogo → <c>/Names /Dests /Kids</c>): recursão sem ciclo
///   nem teto, que desce também em dicionários DIRETOS dentro de <c>/Kids</c>, e visita um nó compartilhado
///   tantas vezes quantos caminhos houver (explosão exponencial).</item>
/// <item><c>DirectObjectFinder.Get/TryGet</c>: segue cadeias <c>n 0 obj  m 0 R</c> por recursão sem teto
///   (usado em <c>/Info</c> → <c>/Title</c> etc.).</item>
/// <item><c>PagesFactory.PopulatePageByNumberDictionary</c>: recursão pela profundidade da árvore de páginas.</item>
/// <item>Força bruta: quando uma referência não está na xref (ou a xref não é legível), o PdfPig varre o arquivo
///   procurando <c>n g obj</c> — inclusive escritos DENTRO de dados de stream.</item>
/// </list>
/// Já protegidos pelo PdfPig: tokenizadores (<c>StackDepthGuard</c> = 64), <c>PdfTokenScanner.Get</c>
/// (navSet + profundidade), cadeia <c>/Prev</c> (conjunto de visitados).
/// <para>
/// MELHOR ESFORÇO, não defesa: a guarda é um pré-filtro. Ela bloqueia o ataque trivial e o conhecido, mas quem
/// controla o arquivo ainda pode encontrar um caminho que o PdfPig percorre e que a guarda não modela — por isso a
/// 0.4.0 isola o <c>Open</c> em processo separado. Dentro dessa limitação o princípio é fail-closed por construção:
/// nada é lido com parser próprio (nomes <c>#xx</c>, comentários, referências e dicionários vêm do
/// <c>CoreTokenScanner</c> do PdfPig; object streams, do mesmo algoritmo do <c>ParseObjectStream</c>) e o que a
/// guarda não entende, ou qualquer teto atingido, RECUSA — nunca trunca.
/// </para>
/// </summary>
internal static class PdfPreOpenGuard
{
    internal const int MaxAliasChain = 32;
    internal const int MaxTreeDepth = 64;
    private const int MaxTokenDepth = 64;
    private const int MaxKidsEdges = 2_000_000;
    private const int MaxTerminalsPerAlias = 1_000;
    private const int MaxXrefRows = 2_000_000;

    private static readonly NameToken XRefName = NameToken.Create("XRef");
    private static readonly NameToken XRefStmName = NameToken.Create("XRefStm");

    private sealed class GuardRefusal(string message) : Exception(message);

    /// <summary>Recusa se o PDF puder derrubar o <c>Open</c>; <c>Encrypted</c> quando há <c>/Encrypt</c> (nem abre).</summary>
    public static PdfGuardResult Check(byte[] content, PdfByteCoverage.Result coverage, ScanBudget budget,
        Action<byte[]>? onDecodedObjectStream = null)
    {
        try
        {
            return CheckCore(content, coverage, budget, onDecodedObjectStream);
        }
        catch (GuardRefusal refusal)
        {
            return new(refusal.Message, false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            // Qualquer coisa que a guarda não soube ler com a semântica do PdfPig é recusa.
            return new($"estrutura não resolvida pela guarda pré-Open ({ex.GetType().Name})", false);
        }
    }

    private static PdfGuardResult CheckCore(byte[] content, PdfByteCoverage.Result coverage, ScanBudget budget,
        Action<byte[]>? onDecoded)
    {
        var sibling = budget.CreateSibling();
        var filterProvider = new BudgetedPdfFilterProvider(sibling);
        long[] objectStarts = [.. coverage.Objects.Select(o => o.Start).OrderBy(x => x)];

        // ---- 1) trailers e objetos de nível superior, tokenizados pelo PdfPig
        bool encrypted = false;
        var sectionStarts = new List<long>(coverage.XrefSectionStarts);
        var linkOffsets = new List<long>(); // /Prev e /XRefStm
        var trailerReferences = new List<int>();
        bool nonZeroGeneration = coverage.XrefNonZeroGeneration;
        int xrefStreams = 0;

        foreach (var (start, end) in coverage.Trailers)
        {
            budget.ThrowIfCancellationRequested();
            if (FirstValue(Tokenize(content, start, end)) is DictionaryToken trailer)
            {
                ReadTrailerKeys(trailer, ref encrypted, linkOffsets);
                CollectReferences(trailer, trailerReferences, 0, ref nonZeroGeneration);
            }
        }

        var summaries = new Dictionary<int, List<PdfObjectSummary>>();
        void Add(int number, PdfObjectSummary summary)
        {
            if (!summaries.TryGetValue(number, out var list)) summaries[number] = list = [];
            list.Add(summary);
        }

        var streamDictionaries = new Dictionary<PdfTopLevelObject, DictionaryToken>();
        int iterations = 0;
        foreach (var item in coverage.Objects)
        {
            if ((++iterations & 1023) == 0) budget.ThrowIfCancellationRequested();

            var tokens = Tokenize(content, item.BodyStart, item.BodyEnd);
            IToken? value;
            int alias = -1;
            if (tokens.Count == 3 && tokens[0] is NumericToken first && tokens[1] is NumericToken
                && ReferenceEquals(tokens[2], OperatorToken.R) && first.Long is >= 0 and <= int.MaxValue)
            {
                alias = (int)first.Long;
                value = null;
                if (((NumericToken)tokens[1]).Long != 0) nonZeroGeneration = true;
            }
            else
            {
                value = tokens.Count == 0 ? null : tokens[^1];
            }

            var summary = Summarize(value, topLevel: true);
            if (alias >= 0)
            {
                summary.AliasTo = alias;
                summary.References = [.. summary.References, alias];
            }

            if (value is DictionaryToken dictionary && item.HasStream)
            {
                streamDictionaries[item] = dictionary;
                if (dictionary.Data.TryGetValue(NameToken.Type, out var type) && type is NameToken name
                    && name.Equals(XRefName))
                {
                    item.IsXRefStream = true;
                    xrefStreams++;
                    sectionStarts.Add(item.Start);
                    ReadTrailerKeys(dictionary, ref encrypted, linkOffsets);
                }
            }

            item.Summary = summary;
            Add(item.Number, summary);
        }

        if (encrypted) return new(null, true);

        if (coverage.Trailers.Count == 0 && xrefStreams == 0)
            throw new GuardRefusal("sem trailer nem xref stream");

        // ---- 2) xref: o que o PdfPig seguirá tem de apontar para objetos/seções que esta guarda leu
        //         (offset dentro de dados de stream ou em lacuna faria o PdfPig ler objeto oculto)
        var entries = new List<(long Offset, int Number)>(coverage.XrefEntries);
        var typeTwoTargets = new HashSet<int>();
        // entradas em uso POR SEÇÃO: o PdfPig só usa as seções da cadeia (último startxref -> /Prev, /XRefStm)
        var inUseBySection = new Dictionary<long, HashSet<int>>(coverage.XrefInUseBySection);
        foreach (var item in coverage.Objects.Where(o => o.IsXRefStream))
        {
            budget.ThrowIfCancellationRequested();
            var sectionInUse = new HashSet<int>();
            inUseBySection[item.Start] = sectionInUse;
            ReadXrefStream(content, item, streamDictionaries[item], filterProvider, sibling, entries,
                typeTwoTargets, sectionInUse, ref nonZeroGeneration);
        }

        long[] sections = [.. sectionStarts.OrderBy(x => x)];
        if (coverage.LastStartxref is not { } lastStartxref || !Points(sections, content, lastStartxref))
            throw new GuardRefusal("startxref final não aponta para uma seção xref lida");
        foreach (long link in linkOffsets)
            if (!Points(sections, content, link))
                throw new GuardRefusal("/Prev ou /XRefStm não aponta para uma seção xref lida");

        // A cadeia de seções como o PdfPig a percorre (FirstPassParser.GetXrefPartsDirectly): ciclo de /Prev, ou offset que
        // não cai EXATAMENTE no início de uma seção, faz o PdfPig descartar a xref inteira ("return []") e usar a força
        // bruta do XrefBruteForcer para TODOS os objetos.
        bool xrefChainBroken = false;
        var reachedSections = new HashSet<long>();
        {
            var trailerStarts = coverage.Trailers.Select(t => t.Start).OrderBy(x => x).ToArray();
            var trailerEnds = coverage.Trailers.OrderBy(t => t.Start).Select(t => t.End).ToArray();
            var previousOf = new Dictionary<long, long>();
            var hybridOf = new Dictionary<long, long>();
            var xrefStreamByStart = coverage.Objects.Where(o => o.IsXRefStream).ToDictionary(o => o.Start);
            foreach (long sectionStart in sections)
            {
                budget.ThrowIfCancellationRequested();
                DictionaryToken? holder = null;
                if (xrefStreamByStart.TryGetValue(sectionStart, out var streamItem))
                    holder = streamDictionaries.GetValueOrDefault(streamItem);
                else
                {
                    int index = Array.BinarySearch(trailerStarts, (int)sectionStart);
                    index = index >= 0 ? index + 1 : ~index;
                    if (index < trailerStarts.Length)
                        holder = FirstValue(Tokenize(content, trailerStarts[index], trailerEnds[index])) as DictionaryToken;
                }

                if (holder is not null && holder.Data.TryGetValue(NameToken.Prev, out var prevToken)
                    && prevToken is NumericToken prevNumber)
                    previousOf[sectionStart] = prevNumber.Long;
                if (holder is not null && streamItem is null && holder.Data.TryGetValue(XRefStmName, out var hybridToken)
                    && hybridToken is NumericToken hybridNumber)
                    hybridOf[sectionStart] = hybridNumber.Long;
            }

            long current = coverage.LastStartxref!.Value;
            var seenSections = new HashSet<long>();
            while (true)
            {
                if (!Points(sections, content, current, out long target)) break;
                if (target != current) xrefChainBroken = true;
                if (!seenSections.Add(target))
                {
                    xrefChainBroken = true;
                    break;
                }

                reachedSections.Add(target);
                if (hybridOf.TryGetValue(target, out long hybrid) && Points(sections, content, hybrid, out long hybridTarget))
                    reachedSections.Add(hybridTarget);

                if (!previousOf.TryGetValue(target, out long next)) break;
                current = next;
            }
        }

        // inUse SÓ com as seções que o PdfPig usa; seção xref fora da cadeia (órfã) é gatilho de força bruta
        // alcançável (fail-closed): o PdfPig ignora as entradas dela, então os objetos que só ela lista seguem sem entrada
        var inUse = new HashSet<int>();
        foreach (long reached in reachedSections)
            if (inUseBySection.TryGetValue(reached, out var reachedNumbers)) inUse.UnionWith(reachedNumbers);
        bool orphanXrefSection = sections.Any(x => !reachedSections.Contains(x));

        iterations = 0;
        var objectByStart = new Dictionary<long, PdfTopLevelObject>();
        foreach (var o in coverage.Objects) objectByStart[o.Start] = o;
        bool entryMismatch = false; // entrada cujo offset leva a OUTRO número de objeto: o PdfPig cai na força bruta por tokens
        foreach (var (offset, entryNumber) in entries)
        {
            if ((++iterations & 4095) == 0) budget.ThrowIfCancellationRequested();
            if (!Points(objectStarts, content, offset, out long target))
                throw new GuardRefusal($"entrada de xref (offset {offset}) não aponta para um objeto de nível superior");
            if (objectByStart[target].Number != entryNumber) entryMismatch = true;
        }
        if (coverage.Objects.Any(o => o.Generation != 0)) nonZeroGeneration = true;

        // ---- 3) object streams: por /N + /First (qualquer /Type) e por entrada tipo 2 da xref
        var byNumber = coverage.Objects.GroupBy(o => o.Number).ToDictionary(g => g.Key, g => g.ToList());
        foreach (int target in typeTwoTargets)
            if (!byNumber.TryGetValue(target, out var holders) || !holders.Any(h => h.HasStream))
                throw new GuardRefusal($"entrada tipo 2 da xref aponta para o objeto {target}, que não é um stream lido");

        foreach (var item in coverage.Objects)
        {
            if (!item.HasStream) continue;
            budget.ThrowIfCancellationRequested();
            bool candidate = typeTwoTargets.Contains(item.Number);
            var dictionary = streamDictionaries.GetValueOrDefault(item);
            if (dictionary is not null && dictionary.Data.ContainsKey(NameToken.N) && dictionary.Data.ContainsKey(NameToken.First))
                candidate = true;
            if (!candidate) continue;
            if (dictionary is null) throw new GuardRefusal($"object stream {item.Number} sem dicionário legível");

            ReadObjectStream(content, item, dictionary, filterProvider, sibling, budget, Add, onDecoded);
        }

        // ---- 3b) FORÇA BRUTA do PdfPig (fonte 0.1.16: ObjectLocationProvider, PdfTokenScanner, FirstPassParser).
        //          O PdfPig varre os bytes crus do arquivo atrás de "N g obj" — em strings, comentários, dados de stream
        //          (com ou sem filtro), em qualquer lugar. E, uma vez que a força bruta roda, os offsets achados por ela
        //          têm PRECEDÊNCIA sobre a xref para TODOS os objetos, inclusive os em uso (TryGetOffset consulta
        //          bruteForcedOffsets antes de offsets; o BruteForceSearcher fica com a ÚLTIMA ocorrência).
        //          Gatilhos modelados (alcançável = qualquer um):
        //            a) referência (inclusive /Length, trailer, membro de ObjStm) para número que não é entrada EM USO;
        //            b) geração diferente de 0 em referência, entrada de xref ou objeto (o PdfPig casa número E geração;
        //               não modelamos pares: qualquer geração != 0 é tratada como gatilho alcançável);
        //            c) entrada tipo 1 cujo offset leva a objeto de OUTRO número (cai na força bruta por tokens);
        //            d) alvo de entrada tipo 2 (o object stream) que não é entrada tipo 1 em uso;
        //            f) seção xref FORA da cadeia (órfã): o PdfPig a ignora; só as seções alcançadas contam como "em uso";
        //            e) cadeia de seções xref em ciclo (/Prev) ou com offset que não cai no início da seção: o PdfPig
        //               descarta a xref inteira e usa o XrefBruteForcer para todos os objetos.
        //          Não determinável com segurança = alcançável (fail-closed).
        //          Alcançável  => recusa QUALQUER ocorrência oculta de número referenciado (ou alvo de ObjStm).
        //          Inalcançável => recusa só ocorrência oculta de número referenciado que não é entrada em uso
        //                          (mantém LC/LD em Clean); sem gatilho a força bruta nunca roda.
        var referenced = new HashSet<int>(trailerReferences);
        foreach (var list in summaries.Values)
            foreach (var summary in list)
            {
                foreach (int reference in summary.References) referenced.Add(reference);
                if (summary.NonZeroGenerationReference) nonZeroGeneration = true;
            }

        bool danglingReference = referenced.Any(n => !inUse.Contains(n));
        bool reachable = danglingReference || nonZeroGeneration || entryMismatch || xrefChainBroken || orphanXrefSection
            || typeTwoTargets.Any(t => !inUse.Contains(t));
        if (reachable) foreach (int target in typeTwoTargets) referenced.Add(target);

        var coveredStarts = new HashSet<long>(coverage.Objects.Select(o => o.Start));
        foreach (var (number, position) in BruteForceOccurrences(content, budget).Concat(BruteForceSearcherOccurrences(content, budget)))
        {
            if (coveredStarts.Contains(position) || !referenced.Contains(number)) continue;
            if (!reachable && inUse.Contains(number)) continue;
            throw new GuardRefusal(
                $"\"{number} g obj\" escondido no offset {position} (fora de qualquer objeto) e o objeto {number} " +
                (reachable
                    ? "é referenciado com a força bruta do PdfPig alcançável: os offsets dela têm precedência sobre a xref"
                    : "é referenciado sem ser entrada em uso da xref: o PdfPig o leria por força bruta"));
        }

        // ---- 4) grafos
        var aliasEdges = new Dictionary<int, Dictionary<int, int>>();
        foreach (var (number, list) in summaries)
            foreach (var summary in list)
                if (summary.AliasTo >= 0) GetEdges(aliasEdges, number)[summary.AliasTo] = 1;

        AnalyzeGraph(aliasEdges, MaxAliasChain, rejectShared: false, "cadeia de referências indiretas");
        var resolver = new AliasResolver(aliasEdges);

        var kidsEdges = new Dictionary<int, Dictionary<int, int>>();
        var parentOf = new Dictionary<int, int>();
        long edgeCount = 0;
        var holderQueue = new Queue<int>();
        var holderSeen = new HashSet<int>();

        void AddEdge(int parent, int rawTarget, int weight)
        {
            foreach (int target in resolver.Terminals(rawTarget))
            {
                var edges = GetEdges(kidsEdges, parent);
                if (edges.TryGetValue(target, out int known))
                {
                    if (weight > known) edges[target] = weight;
                    continue;
                }

                edges[target] = weight;
                if (++edgeCount > MaxKidsEdges) throw new GuardRefusal("grafo /Kids grande demais");
                if ((edgeCount & 4095) == 0) budget.ThrowIfCancellationRequested();
                if (parentOf.TryGetValue(target, out int other) && other != parent)
                    throw new GuardRefusal($"árvore /Kids com nó compartilhado (objeto {target}): a leitura é exponencial");
                parentOf[target] = parent;
            }
        }

        void AddHolder(int parent, int rawHolder, int weight)
        {
            AddEdge(parent, rawHolder, weight);
            foreach (int holder in resolver.Terminals(rawHolder))
                if (holderSeen.Add(holder)) holderQueue.Enqueue(holder);
        }

        void CheckNoRepeats(int number, List<(int Target, int Weight)> edges)
        {
            // [X X]: o FlattenNameTree visita o mesmo filho duas vezes (2^n em cadeia).
            if (edges.Count != edges.Select(e => e.Target).Distinct().Count())
                throw new GuardRefusal($"/Kids com elemento repetido (objeto {number}): a leitura é exponencial");
        }

        foreach (var (number, list) in summaries)
        {
            foreach (var summary in list)
            {
                CheckNoRepeats(number, summary.KidsEdges);
                foreach (var (target, weight) in summary.KidsEdges) AddEdge(number, target, weight);
                foreach (var (holder, weight) in summary.KidsHolders) AddHolder(number, holder, weight);
            }
        }

        // arrays que seguram filhos (/Kids n 0 R): viram nós, com as arestas do que contêm
        while (holderQueue.Count > 0)
        {
            int number = holderQueue.Dequeue();
            if (!summaries.TryGetValue(number, out var list)) continue;
            foreach (var summary in list)
            {
                if (summary.ArrayEdges is null) continue;
                CheckNoRepeats(number, summary.ArrayEdges);
                foreach (var (target, weight) in summary.ArrayEdges) AddEdge(number, target, weight);
                foreach (var (holder, weight) in summary.ArrayHolders) AddHolder(number, holder, weight);
            }
        }

        AnalyzeGraph(kidsEdges, MaxTreeDepth, rejectShared: true, "árvore /Kids");
        return new(null, false);
    }

    // ---------------------------------------------------------------- resumo por objeto (tokens do PdfPig)

    private static PdfObjectSummary Summarize(IToken? value, bool topLevel)
    {
        var summary = new PdfObjectSummary();
        if (value is null) return summary;

        var references = new List<int>();
        bool nonZeroGeneration = false;
        CollectReferences(value, references, 0, ref nonZeroGeneration);
        summary.References = [.. references];
        summary.NonZeroGenerationReference = nonZeroGeneration;

        if (value is DictionaryToken dictionary)
        {
            WalkDictionary(dictionary, 1, summary.KidsEdges, summary.KidsHolders);
        }
        else if (value is ArrayToken array)
        {
            summary.ArrayEdges = [];
            WalkKidsValue(array, 1, summary.ArrayEdges, summary.ArrayHolders);
            // DirectObjectFinder.Get<T>: array de UM elemento que é referência vale como apelido.
            if (topLevel && array.Data.Count == 1 && array.Data[0] is IndirectReferenceToken single
                && single.Data.ObjectNumber is >= 0 and <= int.MaxValue)
                summary.AliasTo = (int)single.Data.ObjectNumber;
        }

        return summary;
    }

    /// <summary>Referências alcançadas por /Kids — descendo em dicionários e arrays DIRETOS (o PdfPig faz o mesmo).</summary>
    private static void WalkDictionary(DictionaryToken dictionary, int weight,
        List<(int, int)> edges, List<(int, int)> holders)
    {
        if (dictionary.Data.TryGetValue(NameToken.Kids, out var kids))
            WalkKidsValue(kids, weight, edges, holders);
    }

    private static void WalkKidsValue(IToken kids, int weight, List<(int, int)> edges, List<(int, int)> holders)
    {
        switch (kids)
        {
            case ArrayToken array:
                foreach (var element in array.Data)
                {
                    if (element is IndirectReferenceToken reference
                        && reference.Data.ObjectNumber is >= 0 and <= int.MaxValue)
                        edges.Add(((int)reference.Data.ObjectNumber, weight));
                    else if (element is DictionaryToken direct)
                        WalkDictionary(direct, weight + 1, edges, holders);
                }
                break;
            case IndirectReferenceToken holder when holder.Data.ObjectNumber is >= 0 and <= int.MaxValue:
                holders.Add(((int)holder.Data.ObjectNumber, weight));
                break;
        }
    }

    /// <summary>TODA referência indireta do valor, recursivamente (profundidade já limitada pelo tokenizador).</summary>
    private static void CollectReferences(IToken token, List<int> output, int depth, ref bool nonZeroGeneration)
    {
        if (depth > MaxTokenDepth + 2) throw new GuardRefusal("valor aninhado demais");
        switch (token)
        {
            case IndirectReferenceToken reference:
                if (reference.Data.ObjectNumber is < 0 or > int.MaxValue)
                    throw new GuardRefusal("referência com número de objeto fora da faixa");
                if (reference.Data.Generation != 0) nonZeroGeneration = true;
                output.Add((int)reference.Data.ObjectNumber);
                break;
            case ArrayToken array:
                foreach (var element in array.Data) CollectReferences(element, output, depth + 1, ref nonZeroGeneration);
                break;
            case DictionaryToken dictionary:
                foreach (var value in dictionary.Data.Values) CollectReferences(value, output, depth + 1, ref nonZeroGeneration);
                break;
        }
    }

    // ---------------------------------------------------------------- tokens do PdfPig

    private static List<IToken> Tokenize(byte[] data, int start, int end, bool isStream = false)
    {
        if (start < 0 || end > data.Length || start > end) throw new GuardRefusal("intervalo inválido");
        var bytes = new MemoryInputBytes(new ReadOnlyMemory<byte>(data, start, end - start));
        var scanner = new CoreTokenScanner(bytes, true, new StackDepthGuard(MaxTokenDepth),
            useLenientParsing: false, isStream: isStream);
        var tokens = new List<IToken>();
        while (scanner.MoveNext())
        {
            if (scanner.CurrentToken is CommentToken) continue;
            tokens.Add(scanner.CurrentToken);
            if (tokens.Count > 64) throw new GuardRefusal("objeto com tokens demais");
        }
        return tokens;
    }

    private static IToken? FirstValue(List<IToken> tokens) => tokens.Count == 0 ? null : tokens[^1];

    private static void ReadTrailerKeys(DictionaryToken dictionary, ref bool encrypted, List<long> links)
    {
        if (dictionary.Data.ContainsKey(NameToken.Encrypt)) encrypted = true;
        foreach (var key in new[] { NameToken.Prev, XRefStmName })
            if (dictionary.Data.TryGetValue(key, out var value))
            {
                if (value is not NumericToken number) throw new GuardRefusal("/Prev ou /XRefStm não numérico");
                links.Add(number.Long);
            }
    }

    /// <summary>
    /// Port FIEL da primeira varredura do <c>XrefBruteForcer</c> do PdfPig 0.1.16 (só a parte que registra objetos):
    /// bytes crus, whitespace normalizado, número = dígitos iniciados após whitespace e fora de comentário,
    /// e "obj" reconhecido pelos 4 últimos bytes normalizados " obj" (sem exigir fronteira depois — "object" também
    /// casa) com o número de objeto &gt; 0 vindo dos dois números anteriores. Zeros à esquerda, qualquer whitespace
    /// (inclusive NUL) e texto dentro de string/stream valem, exatamente como no PdfPig. Devolve (número, offset do
    /// início do número).
    /// </summary>
    internal static IEnumerable<(int Number, long Position)> BruteForceOccurrences(byte[] data, ScanBudget budget)
    {
        static bool Space(byte b) => b is 0 or 9 or 10 or 12 or 13 or 32;

        var digits = new List<byte>(20);
        bool inNumber = false, lastWhitespace = false, inComment = false;
        long first = 0, second = 0, firstPosition = 0, secondPosition = 0;
        uint tail = 0; // últimos 4 bytes normalizados
        const uint ObjTail = ((uint)' ' << 24) | ((uint)'o' << 16) | ((uint)'b' << 8) | 'j';

        void Push(long position)
        {
            string text = System.Text.Encoding.Latin1.GetString([.. digits]);
            if (long.TryParse(text, System.Globalization.NumberStyles.Integer,
                    System.Globalization.CultureInfo.InvariantCulture, out long number))
            {
                first = second; firstPosition = secondPosition;
                second = number; secondPosition = position;
            }
        }

        var results = new List<(int, long)>();
        byte[] last5 = new byte[5];
        for (int i = 0; i < data.Length; i++)
        {
            if ((i & 0xFFFF) == 0) budget.ThrowIfCancellationRequested();
            byte b = data[i];

            if (b == (byte)'%')
            {
                inComment = true;
                if (inNumber && digits.Count > 0)
                {
                    Push(i - digits.Count);
                    digits.Clear();
                }
                inNumber = false;
                lastWhitespace = false;
            }

            byte normalized;
            if (Space(b))
            {
                if (b is 10 or 13) inComment = false;
                normalized = (byte)' ';
                if (inNumber && digits.Count > 0)
                {
                    Push(i - digits.Count);
                    digits.Clear();
                }
                lastWhitespace = true;
                inNumber = false;
            }
            else
            {
                normalized = b;
                if (!inComment && b is >= (byte)'0' and <= (byte)'9' && (inNumber || lastWhitespace))
                {
                    inNumber = true;
                    digits.Add(b);
                }
                else
                {
                    inNumber = false;
                    digits.Clear();
                }
                lastWhitespace = false;
            }

            tail = (tail << 8) | normalized;
            Array.Copy(last5, 1, last5, 0, 4);
            last5[4] = normalized;

            if (tail == ObjTail && first > 0)
            {
                if (first <= int.MaxValue) results.Add(((int)first, firstPosition));
                first = second = 0;
                firstPosition = secondPosition = 0;
            }
            else if (last5.AsSpan().SequenceEqual(" xref"u8) || last5.AsSpan().SequenceEqual("/XRef"u8))
            {
                first = second = 0;
                firstPosition = secondPosition = 0;
            }
        }

        return results;
    }

    /// <summary>
    /// SUPERCONJUNTO do <c>BruteForceSearcher.GetObjectLocations</c> do PdfPig 0.1.16 — o caminho que o
    /// <c>ObjectLocationProvider.TryGetOffset</c> usa quando a referência NÃO está nos offsets da xref (inclui entradas
    /// LIVRES): bytes crus, sem noção de string/comentário/stream, "obj" case-insensitive, whitespace
    /// (qualquer quantidade) entre os números, e o número de objeto pode vir colado a qualquer byte
    /// (<c>(10 0 obj</c>, <c>\xE0 10 0 obj</c>). Aqui NÃO se pula o miolo de objetos ("currentlyInObject") — mais
    /// ocorrências é o lado seguro. Devolve (número, offset do início do número).
    /// </summary>
    internal static IEnumerable<(int Number, long Position)> BruteForceSearcherOccurrences(byte[] data, ScanBudget budget)
    {
        static bool Space(byte b) => b is 0 or 9 or 10 or 12 or 13 or 32;
        static bool Digit(byte b) => b is >= (byte)'0' and <= (byte)'9';

        var results = new List<(int, long)>();
        for (int w = 0; w + 3 < data.Length; w++)
        {
            if ((w & 0xFFFF) == 0) budget.ThrowIfCancellationRequested();
            if (!Space(data[w])) continue;
            if ((data[w + 1] | 0x20) != 'o' || (data[w + 2] | 0x20) != 'b' || (data[w + 3] | 0x20) != 'j') continue;

            int p = w;
            while (p >= 0 && Space(data[p])) p--;
            int generationDigits = 0;
            while (p >= 0 && Digit(data[p])) { p--; generationDigits++; }
            if (generationDigits == 0 || p < 0 || !Space(data[p])) continue;
            while (p >= 0 && Space(data[p])) p--;
            int end = p;
            while (p >= 0 && Digit(data[p])) p--;
            if (p == end) continue;

            if (long.TryParse(System.Text.Encoding.Latin1.GetString(data, p + 1, end - p),
                    System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture,
                    out long number) && number is > 0 and <= int.MaxValue)
                results.Add(((int)number, p + 1));
        }
        return results;
    }

    // O offset da xref pode apontar para whitespace logo antes do alvo.
    private static bool Points(long[] starts, byte[] content, long offset) => Points(starts, content, offset, out _);

    private static bool Points(long[] starts, byte[] content, long offset, out long target)
    {
        target = -1;
        int index = Array.BinarySearch(starts, offset);
        if (index >= 0)
        {
            target = offset;
            return true;
        }

        int next = ~index; // primeiro start > offset
        if (next >= starts.Length || starts[next] - offset > 8) return false;
        target = starts[next];
        for (long position = offset; position < starts[next]; position++)
        {
            if (position < 0 || position >= content.Length) return false;
            if (content[position] is not ((byte)' ' or (byte)'\t' or (byte)'\r' or (byte)'\n' or 0x0C or 0x00)) return false;
        }
        return true;
    }

    // ---------------------------------------------------------------- xref streams

    private static void ReadXrefStream(byte[] content, PdfTopLevelObject item, DictionaryToken dictionary,
        BudgetedPdfFilterProvider filterProvider, ScanBudget sibling, List<(long Offset, int Number)> entries,
        HashSet<int> typeTwoTargets, HashSet<int> inUse, ref bool nonZeroGeneration)
    {
        if (!dictionary.Data.TryGetValue(NameToken.W, out var wToken) || wToken is not ArrayToken wArray
            || wArray.Data.Count != 3 || wArray.Data.Any(x => x is not NumericToken))
            throw new GuardRefusal("xref stream sem /W válido");

        int[] widths = [.. wArray.Data.Cast<NumericToken>().Select(x => x.Int)];
        if (widths.Any(w => w is < 0 or > 8)) throw new GuardRefusal("xref stream com /W fora da faixa");
        int rowWidth = widths.Sum();
        if (rowWidth <= 0) throw new GuardRefusal("xref stream com linha de largura zero");

        // /Index [start count ...]; padrão [0 Size]
        var subsections = new List<(long Start, long Count)>();
        if (dictionary.Data.TryGetValue(NameToken.Index, out var indexToken))
        {
            if (indexToken is not ArrayToken indexArray || indexArray.Data.Count % 2 != 0
                || indexArray.Data.Any(x => x is not NumericToken))
                throw new GuardRefusal("xref stream com /Index inválido");
            for (int i = 0; i < indexArray.Data.Count; i += 2)
                subsections.Add((((NumericToken)indexArray.Data[i]).Long, ((NumericToken)indexArray.Data[i + 1]).Long));
        }
        else
        {
            if (!dictionary.Data.TryGetValue(NameToken.Size, out var sizeToken) || sizeToken is not NumericToken size)
                throw new GuardRefusal("xref stream sem /Size");
            subsections.Add((0, size.Long));
        }

        byte[] raw = content.AsSpan(item.DataStart, item.DataEnd - item.DataStart).ToArray();
        byte[] decoded = PdfStructuralInspector.Decode(new StreamToken(dictionary, raw), filterProvider, sibling);
        long rows = decoded.Length / rowWidth;
        if (rows > MaxXrefRows) throw new GuardRefusal("xref stream grande demais");

        long row = 0;
        foreach (var (start, count) in subsections)
        {
            if (count < 0 || start < 0 || row + count > rows) throw new GuardRefusal("xref stream com /Index maior que o conteúdo");
            for (long k = 0; k < count; k++, row++)
            {
                int at = (int)(row * rowWidth);
                long type = widths[0] == 0 ? 1 : ReadField(decoded, at, widths[0]);
                long second = ReadField(decoded, at + widths[0], widths[1]);
                if (type is 1 or 2 && start + k <= int.MaxValue) inUse.Add((int)(start + k));
                if (type == 1 && widths[2] > 0 && ReadField(decoded, at + widths[0] + widths[1], widths[2]) != 0)
                    nonZeroGeneration = true;
                if (type == 1 && second > 0)
                    entries.Add((second, start + k <= int.MaxValue ? (int)(start + k) : -1));
                else if (type == 2)
                {
                    if (second is < 0 or > int.MaxValue) throw new GuardRefusal("xref stream com alvo de object stream inválido");
                    typeTwoTargets.Add((int)second);
                }
            }
        }
    }

    private static long ReadField(byte[] data, int at, int width)
    {
        long value = 0;
        for (int i = 0; i < width; i++) value = (value << 8) | data[at + i];
        return value;
    }

    // ---------------------------------------------------------------- object streams (mesmo algoritmo do PdfPig)

    private static void ReadObjectStream(byte[] content, PdfTopLevelObject item, DictionaryToken dictionary,
        BudgetedPdfFilterProvider filterProvider, ScanBudget sibling, ScanBudget budget,
        Action<int, PdfObjectSummary> add, Action<byte[]>? onDecoded)
    {
        if (!dictionary.Data.TryGetValue(NameToken.N, out var nToken) || nToken is not NumericToken n
            || !dictionary.Data.TryGetValue(NameToken.First, out var firstToken) || firstToken is not NumericToken first)
            throw new GuardRefusal($"object stream {item.Number} com /N ou /First ausente ou não numérico");
        if (n.Long < 0 || n.Long > 1_000_000 || first.Long < 0)
            throw new GuardRefusal($"object stream {item.Number} com /N ou /First fora da faixa");

        byte[] raw = content.AsSpan(item.DataStart, item.DataEnd - item.DataStart).ToArray();
        byte[] decoded = PdfStructuralInspector.Decode(new StreamToken(dictionary, raw), filterProvider, sibling);
        onDecoded?.Invoke(decoded); // achados léxicos mesmo que a guarda recuse este object stream

        var scanner = new CoreTokenScanner(new MemoryInputBytes(decoded), true, new StackDepthGuard(MaxTokenDepth),
            useLenientParsing: false, isStream: true);

        var objects = new List<(long Number, long Offset)>();
        for (int i = 0; i < n.Int; i++)
        {
            if (!scanner.MoveNext() || scanner.CurrentToken is not NumericToken number)
                throw new GuardRefusal($"object stream {item.Number}: cabeçalho ilegível");
            if (!scanner.MoveNext() || scanner.CurrentToken is not NumericToken offset)
                throw new GuardRefusal($"object stream {item.Number}: cabeçalho ilegível");
            objects.Add((number.Long, first.Long + offset.Long));
        }

        foreach (var (number, offset) in objects)
        {
            budget.ThrowIfCancellationRequested();
            sibling.ConsumePdfObject();

            bool isBetween = ((offset - (scanner.CurrentPosition - 1)) | ((scanner.CurrentPosition + 1) - offset)) >= 0;
            if (!isBetween)
            {
                if (offset < 0 || offset >= decoded.Length)
                    throw new GuardRefusal($"object stream {item.Number}: offset de membro fora do conteúdo");
                scanner.Seek(offset);
            }

            if (!scanner.MoveNext()) throw new GuardRefusal($"object stream {item.Number}: membro ilegível");
            var token = scanner.CurrentToken;
            if (token.Equals(OperatorToken.EndObject))
            {
                if (!scanner.MoveNext()) throw new GuardRefusal($"object stream {item.Number}: membro ilegível");
                token = scanner.CurrentToken;
            }

            if (number is < 0 or > int.MaxValue) throw new GuardRefusal($"object stream {item.Number}: número de membro inválido");
            add((int)number, Summarize(token, topLevel: false));
        }
    }

    // ---------------------------------------------------------------- grafos

    private static Dictionary<int, int> GetEdges(Dictionary<int, Dictionary<int, int>> map, int key)
    {
        if (!map.TryGetValue(key, out var set)) map[key] = set = [];
        return set;
    }

    /// <summary>Terminais de uma cadeia de apelidos, memoizados; passar do teto RECUSA (nunca trunca).</summary>
    private sealed class AliasResolver(Dictionary<int, Dictionary<int, int>> edges)
    {
        private readonly Dictionary<int, int[]> _memo = [];

        public int[] Terminals(int node, int depth = 0)
        {
            if (_memo.TryGetValue(node, out var known)) return known;
            if (depth > MaxAliasChain + 2) throw new GuardRefusal("cadeia de referências indiretas longa demais");

            int[] result;
            if (edges.TryGetValue(node, out var next) && next.Count > 0)
            {
                var all = new HashSet<int>();
                foreach (int target in next.Keys)
                {
                    foreach (int terminal in Terminals(target, depth + 1)) all.Add(terminal);
                    if (all.Count > MaxTerminalsPerAlias) throw new GuardRefusal("apelido com alvos demais");
                }
                result = [.. all];
            }
            else
            {
                result = [node];
            }

            _memo[node] = result;
            return result;
        }
    }

    /// <summary>Kahn iterativo com pesos: ciclo, nó compartilhado (opcional) e caminho mais longo, sem recursão.</summary>
    private static void AnalyzeGraph(Dictionary<int, Dictionary<int, int>> edges, int maxDepth, bool rejectShared, string what)
    {
        if (edges.Count == 0) return;

        var indegree = new Dictionary<int, int>();
        foreach (var (node, targets) in edges)
        {
            indegree.TryAdd(node, 0);
            foreach (int target in targets.Keys)
            {
                indegree[target] = indegree.GetValueOrDefault(target) + 1;
                if (rejectShared && indegree[target] > 1)
                    throw new GuardRefusal($"{what} com nó compartilhado (objeto {target}): a leitura é exponencial");
            }
        }

        var depth = new Dictionary<int, int>();
        var ready = new Queue<int>(indegree.Where(pair => pair.Value == 0).Select(pair => pair.Key));
        int processed = 0;
        while (ready.Count > 0)
        {
            int node = ready.Dequeue();
            processed++;
            int nodeDepth = depth.GetValueOrDefault(node);
            if (nodeDepth > maxDepth) throw new GuardRefusal($"{what} com mais de {maxDepth} níveis");

            if (!edges.TryGetValue(node, out var targets)) continue;
            foreach (var (target, weight) in targets)
            {
                depth[target] = Math.Max(depth.GetValueOrDefault(target), nodeDepth + weight);
                if (--indegree[target] == 0) ready.Enqueue(target);
            }
        }

        if (processed < indegree.Count) throw new GuardRefusal($"{what} cíclica");
    }
}
