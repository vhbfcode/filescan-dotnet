using System.Text;

namespace FileScan.Scanning;

/// <summary>
/// Tabelas de marcadores de conteúdo ativo e utilitários de busca, compartilhados entre os inspetores.
/// A busca é case-insensitive (ASCII): o buffer é "foldado" para minúsculo antes de procurar,
/// e os tokens são definidos já em minúsculo.
/// </summary>
internal static class ActiveContentMarkers
{
    // Marcadores de script para contexto de TEXTO (HTML, partes XML de OOXML, CSV).
    public static readonly (byte[] Token, string Label)[] Script = Build(
        ("<script",     "script HTML (<script>)"),
        ("<?php",       "código PHP (<?php)"),
        ("<%",          "scriptlet ASP/JSP (<%)"),
        ("javascript:", "URI javascript:"),
        ("vbscript:",   "URI vbscript:"),
        ("onerror=",    "handler de evento (onerror=)"),
        ("onload=",     "handler de evento (onload=)"));

    // Versão para varrer bytes BINÁRIOS (imagens, OLE2): só sequências longas o bastante para não
    // casarem por acaso. Remove o "<%" (2 bytes), que aparece aleatoriamente em qualquer foto real.
    public static readonly (byte[] Token, string Label)[] ScriptBinarySafe = Build(
        ("<script",     "script HTML (<script>)"),
        ("<?php",       "código PHP (<?php)"),
        ("javascript:", "URI javascript:"),
        ("vbscript:",   "URI vbscript:"),
        ("onerror=",    "handler de evento (onerror=)"),
        ("onload=",     "handler de evento (onload=)"));

    // HYPERLINK() foi tirado de propósito: é função normal e benigna do Excel (link clicável).
    // O perigoso de verdade é DDE/cmd e funções de busca remota (exfiltração).
    public static readonly (byte[] Token, string Label)[] OfficeDanger = Build(
        ("ddeauto",     "DDE auto-exec (DDEAUTO)"),
        ("cmd|",        "comando externo (cmd|)"),
        ("webservice(", "função WEBSERVICE()"),
        ("importxml(",  "função IMPORTXML()"),
        ("importdata(", "função IMPORTDATA()"));

    public static readonly (byte[] Token, string Label)[] Macro = Build(
        ("vbaproject",    "macro VBA (vbaProject)"),
        ("auto_open",     "macro auto-exec (Auto_Open)"),
        ("autoopen",      "macro auto-exec (AutoOpen)"),
        ("workbook_open", "macro auto-exec (Workbook_Open)"),
        ("document_open", "macro auto-exec (Document_Open)"));

    private static (byte[], string)[] Build(params (string Token, string Label)[] items)
    {
        var result = new (byte[], string)[items.Length];
        for (int i = 0; i < items.Length; i++)
            result[i] = (Encoding.ASCII.GetBytes(items[i].Token), items[i].Label);
        return result;
    }

    /// <summary>Cópia do buffer com os ASCII A-Z rebaixados para minúsculo.</summary>
    public static byte[] ToLowerAscii(ReadOnlySpan<byte> data)
    {
        var r = data.ToArray();
        for (int i = 0; i < r.Length; i++)
            if (r[i] >= (byte)'A' && r[i] <= (byte)'Z')
                r[i] += 32;
        return r;
    }

    /// <summary>Cópia sem bytes nulos — colapsa nomes UTF-16 (ex.: streams de OLE2) para ASCII.</summary>
    public static byte[] StripNulls(ReadOnlySpan<byte> data)
    {
        var r = new byte[data.Length];
        int n = 0;
        foreach (var b in data)
            if (b != 0) r[n++] = b;
        return r[..n];
    }

    /// <summary>Procura cada marcador no buffer (ambos já minúsculos) e adiciona o rótulo se achar.</summary>
    public static void ScanLower(ReadOnlySpan<byte> lower, (byte[] Token, string Label)[] markers,
        List<string> found, HashSet<string> seen)
    {
        foreach (var (token, label) in markers)
        {
            if (seen.Contains(label)) continue;
            if (lower.IndexOf(token.AsSpan()) >= 0)
            {
                found.Add(label);
                seen.Add(label);
            }
        }
    }
}
