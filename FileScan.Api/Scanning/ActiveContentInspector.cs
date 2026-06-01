using System.IO.Compression;

namespace FileScan.Scanning;

public enum FileKind { Pdf, Ooxml, Ole2, Image, Csv, Text }

/// <summary>
/// Detector de conteúdo ativo multi-formato. Despacha por tipo de arquivo (magic bytes + extensão)
/// e procura os marcadores de injeção de script de cada família. Não é antivírus nem CDR:
/// detecta e devolve os achados; a política (Reject/Flag/Ignore) é aplicada pelo serviço.
/// </summary>
public static class ActiveContentInspector
{
    private const int MaxOoxmlEntries = 512;
    private const int MaxEntryBytes = 16 * 1024 * 1024;

    public static IReadOnlyList<string> Inspect(string fileName, byte[] content) =>
        Detect(fileName, content) switch
        {
            FileKind.Pdf => PdfActiveContentInspector.Inspect(content),
            FileKind.Ooxml => InspectOoxml(content),
            FileKind.Ole2 => InspectBinaryOffice(content),
            FileKind.Image => InspectImage(content),
            FileKind.Csv => InspectCsv(content),
            _ => InspectText(content),
        };

    public static FileKind Detect(string fileName, ReadOnlySpan<byte> c)
    {
        if (c.Length >= 4 && c[0] == (byte)'%' && c[1] == (byte)'P' && c[2] == (byte)'D' && c[3] == (byte)'F') return FileKind.Pdf;
        if (c.Length >= 4 && c[0] == 0x50 && c[1] == 0x4B && c[2] == 0x03 && c[3] == 0x04) return FileKind.Ooxml; // PK.. (zip/OOXML)
        if (c.Length >= 8 && c[0] == 0xD0 && c[1] == 0xCF && c[2] == 0x11 && c[3] == 0xE0) return FileKind.Ole2;  // OLE2 (doc/xls legado)
        if (c.Length >= 4 && c[0] == 0x89 && c[1] == 0x50 && c[2] == 0x4E && c[3] == 0x47) return FileKind.Image; // PNG
        if (c.Length >= 3 && c[0] == 0xFF && c[1] == 0xD8 && c[2] == 0xFF) return FileKind.Image;                 // JPEG
        if (c.Length >= 4 && c[0] == (byte)'G' && c[1] == (byte)'I' && c[2] == (byte)'F' && c[3] == (byte)'8') return FileKind.Image; // GIF

        var ext = Path.GetExtension(fileName).TrimStart('.').ToLowerInvariant();
        return ext == "csv" ? FileKind.Csv : FileKind.Text;
    }

    // --- Texto / HTML / legado renomeado ---
    private static List<string> InspectText(byte[] content)
    {
        var found = new List<string>();
        var seen = new HashSet<string>();
        var lower = ActiveContentMarkers.ToLowerAscii(content);
        ActiveContentMarkers.ScanLower(lower, ActiveContentMarkers.Script, found, seen);
        ActiveContentMarkers.ScanLower(lower, ActiveContentMarkers.OfficeDanger, found, seen);
        return found;
    }

    // --- OLE2 binário (doc/xls legado) ---
    private static List<string> InspectBinaryOffice(byte[] content)
    {
        var found = new List<string>();
        var seen = new HashSet<string>();
        var lower = ActiveContentMarkers.ToLowerAscii(content);
        ActiveContentMarkers.ScanLower(lower, ActiveContentMarkers.ScriptBinarySafe, found, seen);
        ActiveContentMarkers.ScanLower(lower, ActiveContentMarkers.OfficeDanger, found, seen);
        ActiveContentMarkers.ScanLower(lower, ActiveContentMarkers.Macro, found, seen);

        // Nomes de stream em OLE2 são UTF-16; colapsa os nulos e procura as macros de novo.
        var denull = ActiveContentMarkers.ToLowerAscii(ActiveContentMarkers.StripNulls(content));
        ActiveContentMarkers.ScanLower(denull, ActiveContentMarkers.Macro, found, seen);
        return found;
    }

    // --- Imagens (jpg/png/gif) ---
    // Procura só script EMBUTIDO (metadata/comentário/append) com marcadores longos o bastante para
    // não casarem por acaso nos bytes da imagem. NÃO sinaliza "dados após o fim": fotos reais costumam
    // ter metadata/thumbnail/padding após o EOI, o que daria falso-positivo. Script anexado continua
    // pego pelos marcadores (<script>, <?php, ...). Polyglot só-binário (sem script) fica fora do
    // escopo daqui — seria caso de CDR/análise mais profunda.
    private static List<string> InspectImage(byte[] content)
    {
        var found = new List<string>();
        var seen = new HashSet<string>();
        var lower = ActiveContentMarkers.ToLowerAscii(content);
        ActiveContentMarkers.ScanLower(lower, ActiveContentMarkers.ScriptBinarySafe, found, seen);
        return found;
    }

    // --- CSV ---
    private static List<string> InspectCsv(byte[] content)
    {
        var found = new List<string>();
        var seen = new HashSet<string>();
        var lower = ActiveContentMarkers.ToLowerAscii(content);
        ActiveContentMarkers.ScanLower(lower, ActiveContentMarkers.OfficeDanger, found, seen);
        ActiveContentMarkers.ScanLower(lower, ActiveContentMarkers.Script, found, seen);

        if (HasCsvFormulaInjection(content))
            found.Add("célula iniciando com caractere de fórmula (= + - @ Tab — OWASP CSV injection)");
        return found;
    }

    // Regra OWASP de CSV injection: campo cujo 1º caractere é '=' '@' ou Tab (sempre), ou '+'/'-' quando
    // o campo PARECE fórmula (tem letra, '(' ou '|') — assim não rejeita número negativo/telefone.
    private static bool HasCsvFormulaInjection(byte[] content)
    {
        int i = (content.Length >= 3 && content[0] == 0xEF && content[1] == 0xBB && content[2] == 0xBF) ? 3 : 0; // pula BOM UTF-8
        var field = new List<byte>(64);
        bool inQuotes = false;

        for (; i < content.Length; i++)
        {
            byte b = content[i];
            if (inQuotes)
            {
                if (b == (byte)'"') inQuotes = false;
                else field.Add(b);
            }
            else if (b == (byte)'"')
            {
                inQuotes = true;
            }
            else if (b == (byte)',' || b == (byte)';' || b == (byte)'\n' || b == (byte)'\r')
            {
                if (IsInjectionField(field)) return true;
                field.Clear();
            }
            else
            {
                field.Add(b);
            }
        }
        return IsInjectionField(field);
    }

    private static bool IsInjectionField(List<byte> field)
    {
        int k = 0;
        while (k < field.Count && field[k] == (byte)' ') k++; // espaço-prefixo não vira fórmula no Excel
        if (k >= field.Count) return false;

        byte first = field[k];
        if (first == (byte)'=' || first == (byte)'@' || first == (byte)'\t') return true;

        if (first == (byte)'+' || first == (byte)'-')
        {
            for (int j = k + 1; j < field.Count; j++)
            {
                byte c = field[j];
                if (c == (byte)'(' || c == (byte)'|'
                    || (c >= (byte)'A' && c <= (byte)'Z') || (c >= (byte)'a' && c <= (byte)'z'))
                    return true;
            }
        }
        return false;
    }

    // --- OOXML (docx/xlsx = zip) ---
    private static List<string> InspectOoxml(byte[] content)
    {
        var found = new List<string>();
        var seen = new HashSet<string>();
        try
        {
            using var ms = new MemoryStream(content, writable: false);
            using var zip = new ZipArchive(ms, ZipArchiveMode.Read);

            int count = 0;
            foreach (var entry in zip.Entries)
            {
                if (++count > MaxOoxmlEntries) break;
                var name = entry.FullName.ToLowerInvariant();

                if (name.Contains("vbaproject") && seen.Add("ooxml-macro"))
                    found.Add("macro VBA embutida (vbaProject.bin)");
                if ((name.Contains("/embeddings/") || name.Contains("oleobject")) && seen.Add("ooxml-ole"))
                    found.Add("objeto OLE embutido");

                var data = ReadEntry(entry);
                if (data.Length == 0) continue;

                var lower = ActiveContentMarkers.ToLowerAscii(data);
                ActiveContentMarkers.ScanLower(lower, ActiveContentMarkers.Script, found, seen);
                ActiveContentMarkers.ScanLower(lower, ActiveContentMarkers.OfficeDanger, found, seen);
                ActiveContentMarkers.ScanLower(lower, ActiveContentMarkers.Macro, found, seen);
            }
        }
        catch
        {
            // ZIP inválido/criptografado — nada a inspecionar aqui (o antivírus ainda roda depois).
        }
        return found;
    }

    private static byte[] ReadEntry(ZipArchiveEntry entry)
    {
        try
        {
            using var es = entry.Open();
            using var outMs = new MemoryStream();
            var buf = new byte[81920];
            int total = 0, read;
            while ((read = es.Read(buf, 0, buf.Length)) > 0)
            {
                total += read;
                if (total > MaxEntryBytes)
                {
                    outMs.Write(buf, 0, read - (total - MaxEntryBytes));
                    break;
                }
                outMs.Write(buf, 0, read);
            }
            return outMs.ToArray();
        }
        catch
        {
            return [];
        }
    }
}
