using System.Diagnostics;
using Xunit;

namespace FileScan.Tests;

/// <summary>
/// Teste DIFERENCIAL da guarda pré-Open (VOLTA r5). Gera variações dos ataques que derrubam o
/// <c>PdfDocument.Open</c> do PdfPig 0.1.16 — escapes <c>#xx</c> em chaves relevantes, comentários dentro de
/// referências, ObjStm com e sem <c>/Type</c> (e com <c>/Extends</c>), revisões em que o ciclo está na
/// definição antiga ou na nova — e exige <c>NotInspected</c> em TODAS, sem derrubar o processo. A varredura
/// roda em um PROCESSO FILHO (<c>FileScan.Tests.Child</c>) com timeout: se algum contorno voltar, o filho morre
/// (estouro de pilha) ou trava (2^n) e este teste aponta QUAL arquivo, em vez de abortar a run inteira.
/// Os controles <c>legit_*</c> (mesmas transformações, estruturas reais) exigem <c>Clean</c>: a guarda não pode
/// recusar o que o PdfPig lê normalmente.
/// </summary>
public class Pdf030GuardDifferentialTests
{
    private static readonly (string Name, Func<string, string> Apply)[] Transforms =
    [
        ("id", text => text),
        ("kids", text => text.Replace("/Kids", "/K#69ds")),
        ("names", text => text.Replace("/Names", "/N#61mes").Replace("/Dests", "/D#65sts")),
        ("type", text => text.Replace("/Type", "/T#79pe")),
        ("pages", text => text.Replace("/Pages", "/P#61ges").Replace("/Parent", "/Par#65nt")),
        ("tudo", text => text.Replace("/Kids", "/K#69ds").Replace("/Names", "/N#61mes").Replace("/Dests", "/D#65sts")
            .Replace("/Type", "/T#79pe").Replace("/Pages", "/P#61ges").Replace("/Parent", "/Par#65nt")),
        ("comentario", text => text.Replace(" 0 R", " %c\n0 R")),
    ];

    private static byte[] Build(Func<string, string> transform, Func<byte[]> make)
    {
        Samples.BodyTransform = transform;
        try { return make(); }
        finally { Samples.BodyTransform = null; }
    }

    private static string ChildPath()
    {
        var tfm = new DirectoryInfo(AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar));
        var configuration = tfm.Parent!;
        var repository = configuration.Parent!.Parent!.Parent!;
        return Path.Combine(repository.FullName, "FileScan.Tests.Child", "bin", configuration.Name, tfm.Name,
            "FileScan.Tests.Child.dll");
    }

    [Fact]
    public void VariationsOfTheAttacks_AreNotInspected_NeverCrashTheProcess()
    {
        var directory = Directory.CreateTempSubdirectory("filescan-diff-").FullName;
        var expected = new SortedDictionary<string, ScanVerdictExpectation>(StringComparer.Ordinal);
        try
        {
            void Emit(string name, ScanVerdictExpectation expectation, byte[] bytes)
            {
                File.WriteAllBytes(Path.Combine(directory, name + ".pdf"), bytes);
                expected[name + ".pdf"] = expectation;
            }

            foreach (var (transformName, apply) in Transforms)
            {
                void Attack(string name, Func<byte[]> make) =>
                    Emit($"ataque_{name}__{transformName}", ScanVerdictExpectation.NotInspected, Build(apply, make));

                Attack("dests_ciclo2", () => Samples.PdfWithDests(2, cycle: true));
                Attack("dests_cadeia5000", () => Samples.PdfWithDests(5_000));
                Attack("paginas20000", () => Samples.PdfWithDeepPageTree(20_000));
                Attack("info_autoalias", Samples.PdfWithInfoValueSelfAlias);
                Attack("oculto_em_stream", Samples.PdfWithHiddenObjectsInsideStream);

                // VOLTA r6: filhos DIRETOS em /Kids (Y1..Y3) e objetos escritos em dados de stream fora da xref (B1/B3/B5)
                Attack("y1_kids_direto", () => Samples.PdfWithDestsDirectKids(1));
                Attack("y2_kids_direto2", () => Samples.PdfWithDestsDirectKids(2));
                Attack("y3_kids_array_com_dict", Samples.PdfWithDestsKidsHeldByAnArrayWithDirectDictionary);
                Attack("f1_dct_com_objetos_livres", () => Samples.PdfWithCycleHiddenAndMarkedFree("dct"));
                Attack("f2_comentario_com_objetos_livres", () => Samples.PdfWithCycleHiddenAndMarkedFree("comment"));
                Attack("f3_string_com_objetos_livres", () => Samples.PdfWithCycleHiddenAndMarkedFree("string"));
                Attack("t1_string_no_em_uso_pendente", () => Samples.PdfWithHiddenCopyOfInUseNode("string", "dangling"));
                Attack("t2_comentario_no_em_uso_pendente", () => Samples.PdfWithHiddenCopyOfInUseNode("comment", "dangling"));
                Attack("t3_dct_no_em_uso_pendente", () => Samples.PdfWithHiddenCopyOfInUseNode("dct", "dangling"));
                Attack("t7_objstm_oculto_pendente", () => Samples.PdfWithHiddenCopyOfTheObjectStream("dangling"));
                Attack("t8_objstm_container_livre", () => Samples.PdfWithHiddenCopyOfTheObjectStream("containerFree"));
                Attack("t9_prev_ciclico", () => Samples.PdfWithSelfReferencingPrev(hiddenCopy: true));
                Attack("o1_secao_xref_orfa", () => Samples.PdfWithOrphanXrefSection(hiddenCopy: true));
                Attack("t5_geracao", () => Samples.PdfWithHiddenCopyOfInUseNode("string", "generation"));
                Attack("t6_offsets_trocados", () => Samples.PdfWithHiddenCopyOfInUseNode("comment", "mismatch"));
                Attack("b1_stream_fora_da_xref", () => Samples.PdfWithCycleOnlyInsideStreamData());
                Attack("b3_xref_19_bytes", () => Samples.PdfWithCycleOnlyInsideStreamData("19"));
                Attack("b5_xref_cabecalho_com_espaco", () => Samples.PdfWithCycleOnlyInsideStreamData("headerspace"));

                // ObjStm com e sem /Type, /Type escapado, /Extends
                foreach (var (label, typePart, extra) in new[]
                         {
                             ("objstm", "/Type/ObjStm", ""), ("objstm_semtype", "", ""),
                             ("objstm_typeescapado", "/Type/Obj#53tm", ""), ("objstm_extends", "", "/Extends 99 0 R"),
                         })
                {
                    Attack($"dests_ciclo2_{label}", () => Samples.PdfWithObjectStream(
                        Samples.ObjectStreamDocument("/Names<</Dests 10 0 R>>", Samples.DestsChain(2, cycle: true)),
                        typePart, extra));
                }
                Attack("dests_cadeia5000_objstm_semtype", () => Samples.PdfWithObjectStream(
                    Samples.ObjectStreamDocument("/Names<</Dests 10 0 R>>", Samples.DestsChain(5_000)), ""));

                // revisões: ciclo na definição ANTIGA (a nova o quebra) e ciclo na definição NOVA
                Attack("revisao_ciclo_antigo", () => Samples.AppendUpdate(Samples.PdfWithDests(2, cycle: true),
                    (10, "<</Names[(a)[3 0 R/Fit]]>>")));
                Attack("revisao_ciclo_novo", () => Samples.AppendUpdate(Samples.PdfWithDests(3),
                    (12, "<</Kids[10 0 R]>>")));

                // controles legítimos: as mesmas transformações NÃO podem fazer a guarda recusar o que é normal.
                // (Comentário DENTRO de uma referência "n %c 0 R" não é legítimo para a gramática de cobertura:
                // é recusado como lacuna — fail-closed, ver "limitações conhecidas" no CHANGELOG.)
                if (transformName == "comentario") continue;
                Emit($"legit_dests3__{transformName}", ScanVerdictExpectation.Clean,
                    Build(apply, () => Samples.PdfWithDests(3)));
                Emit($"legit_objstm_dests3__{transformName}", ScanVerdictExpectation.Clean,
                    Build(apply, () => Samples.PdfWithObjectStream(
                        Samples.ObjectStreamDocument("/Names<</Dests 10 0 R>>", Samples.DestsChain(3)))));
                Emit($"legit_paginas5__{transformName}", ScanVerdictExpectation.Clean,
                    Build(apply, () => Samples.PdfWithDeepPageTree(5)));
            }

            var child = ChildPath();
            Assert.True(File.Exists(child), $"processo filho não encontrado: {child}");

            var info = new ProcessStartInfo("dotnet", $"\"{child}\" \"{directory}\"")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
            };
            using var process = Process.Start(info)!;
            var output = new List<string>();
            process.OutputDataReceived += (_, e) => { if (e.Data is not null) lock (output) output.Add(e.Data); };
            process.ErrorDataReceived += (_, _) => { };
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();

            bool exited = process.WaitForExit(240_000);
            if (!exited) process.Kill(entireProcessTree: true);
            process.WaitForExit(); // esvazia os handlers de saída

            string[] lines;
            lock (output) lines = [.. output];
            var verdicts = lines.Select(l => l.Split('\t')).Where(p => p.Length == 2).ToDictionary(p => p[0], p => p[1]);

            var names = expected.Keys.ToList();
            var firstMissing = names.FirstOrDefault(n => !verdicts.ContainsKey(n));
            Assert.True(exited && process.ExitCode == 0 && firstMissing is null,
                exited
                    ? $"processo filho terminou com exit code {process.ExitCode} (estouro de pilha?) antes de {firstMissing}"
                    : $"processo filho TRAVOU (timeout) em {firstMissing}");

            var wrong = names.Where(n => verdicts[n] != expected[n].ToString()).Select(n => $"{n}: {verdicts[n]}").ToList();
            Assert.True(wrong.Count == 0, "vereditos inesperados:\n" + string.Join("\n", wrong));
        }
        finally
        {
            try { Directory.Delete(directory, recursive: true); } catch (IOException) { }
        }
    }

    private enum ScanVerdictExpectation { NotInspected, Clean }
}
