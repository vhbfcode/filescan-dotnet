namespace FileScan.Tests;

/// <summary>
/// Corpus de ATAQUES contra o <c>PdfDocument.Open</c> do PdfPig 0.1.16 que a guarda pré-Open da 0.3.0 cobre
/// (extraído do teste diferencial para ser compartilhado com os testes de aceitação do isolamento em worker).
/// Quem chama pode envolver <see cref="Register"/> em <c>Samples.BodyTransform</c> para gerar variações (escapes #xx).
/// </summary>
internal static class GuardAttackCorpus
{
    public static void Register(Action<string, Func<byte[]>> attack)
    {
        attack("dests_ciclo2", () => Samples.PdfWithDests(2, cycle: true));
        attack("dests_cadeia5000", () => Samples.PdfWithDests(5_000));
        attack("paginas20000", () => Samples.PdfWithDeepPageTree(20_000));
        attack("info_autoalias", Samples.PdfWithInfoValueSelfAlias);
        attack("oculto_em_stream", Samples.PdfWithHiddenObjectsInsideStream);

        // VOLTA r6: filhos DIRETOS em /Kids (Y1..Y3) e objetos escritos em dados de stream fora da xref (B1/B3/B5)
        attack("y1_kids_direto", () => Samples.PdfWithDestsDirectKids(1));
        attack("y2_kids_direto2", () => Samples.PdfWithDestsDirectKids(2));
        attack("y3_kids_array_com_dict", Samples.PdfWithDestsKidsHeldByAnArrayWithDirectDictionary);
        attack("f1_dct_com_objetos_livres", () => Samples.PdfWithCycleHiddenAndMarkedFree("dct"));
        attack("f2_comentario_com_objetos_livres", () => Samples.PdfWithCycleHiddenAndMarkedFree("comment"));
        attack("f3_string_com_objetos_livres", () => Samples.PdfWithCycleHiddenAndMarkedFree("string"));
        attack("t1_string_no_em_uso_pendente", () => Samples.PdfWithHiddenCopyOfInUseNode("string", "dangling"));
        attack("t2_comentario_no_em_uso_pendente", () => Samples.PdfWithHiddenCopyOfInUseNode("comment", "dangling"));
        attack("t3_dct_no_em_uso_pendente", () => Samples.PdfWithHiddenCopyOfInUseNode("dct", "dangling"));
        attack("t7_objstm_oculto_pendente", () => Samples.PdfWithHiddenCopyOfTheObjectStream("dangling"));
        attack("t8_objstm_container_livre", () => Samples.PdfWithHiddenCopyOfTheObjectStream("containerFree"));
        attack("t9_prev_ciclico", () => Samples.PdfWithSelfReferencingPrev(hiddenCopy: true));
        attack("o1_secao_xref_orfa", () => Samples.PdfWithOrphanXrefSection(hiddenCopy: true));
        attack("t5_geracao", () => Samples.PdfWithHiddenCopyOfInUseNode("string", "generation"));
        attack("t6_offsets_trocados", () => Samples.PdfWithHiddenCopyOfInUseNode("comment", "mismatch"));
        attack("b1_stream_fora_da_xref", () => Samples.PdfWithCycleOnlyInsideStreamData());
        attack("b3_xref_19_bytes", () => Samples.PdfWithCycleOnlyInsideStreamData("19"));
        attack("b5_xref_cabecalho_com_espaco", () => Samples.PdfWithCycleOnlyInsideStreamData("headerspace"));

        // ObjStm com e sem /Type, /Type escapado, /Extends
        foreach (var (label, typePart, extra) in new[]
                 {
                     ("objstm", "/Type/ObjStm", ""), ("objstm_semtype", "", ""),
                     ("objstm_typeescapado", "/Type/Obj#53tm", ""), ("objstm_extends", "", "/Extends 99 0 R"),
                 })
        {
            attack($"dests_ciclo2_{label}", () => Samples.PdfWithObjectStream(
                Samples.ObjectStreamDocument("/Names<</Dests 10 0 R>>", Samples.DestsChain(2, cycle: true)),
                typePart, extra));
        }
        attack("dests_cadeia5000_objstm_semtype", () => Samples.PdfWithObjectStream(
            Samples.ObjectStreamDocument("/Names<</Dests 10 0 R>>", Samples.DestsChain(5_000)), ""));

        // revisões: ciclo na definição ANTIGA (a nova o quebra) e ciclo na definição NOVA
        attack("revisao_ciclo_antigo", () => Samples.AppendUpdate(Samples.PdfWithDests(2, cycle: true),
            (10, "<</Names[(a)[3 0 R/Fit]]>>")));
        attack("revisao_ciclo_novo", () => Samples.AppendUpdate(Samples.PdfWithDests(3),
            (12, "<</Kids[10 0 R]>>")));
    }
}
