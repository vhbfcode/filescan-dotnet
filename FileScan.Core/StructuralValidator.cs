using MimeDetective;
using MimeDetective.Definitions;

namespace FileScan.Scanning;

/// <summary>
/// Primeira linha (barata, síncrona): tamanho, extensão e TIPO REAL do conteúdo (via Mime-Detective).
/// Verifica o tipo de verdade pelos bytes — não confia só na extensão — recusando binário perigoso
/// (executável) e arquivos cujo conteúdo não bate com a extensão declarada. Complementa o scan antivírus.
/// </summary>
public sealed class StructuralValidator
{
    // O build do inspector é caro (compila as definições); compartilhado entre instâncias que não
    // injetam um próprio. Definições Default do Mime-Detective = livres para uso comercial.
    private static readonly Lazy<IContentInspector> DefaultInspector = new(() =>
        new ContentInspectorBuilder { Definitions = DefaultDefinitions.All() }.Build());

    private readonly FileScannerOptions _opt;
    private readonly IContentInspector _inspector;

    public StructuralValidator(FileScannerOptions options, IContentInspector? inspector = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        _opt = options.Snapshot();
        _opt.Validate();
        _inspector = inspector ?? DefaultInspector.Value;
    }

    /// <summary>Retorna o motivo da reprovação, ou null se passou.</summary>
    public string? Validate(string fileName, byte[] content)
    {
        long size = content.LongLength;
        if (size <= 0)
            return "arquivo vazio";

        if (size > _opt.MaxFileSizeBytes)
            return $"tamanho {size} excede o máximo de {_opt.MaxFileSizeBytes} bytes";

        var ext = Path.GetExtension(fileName).TrimStart('.').ToLowerInvariant();

        if (_opt.AllowedExtensions.Length > 0 && !_opt.AllowedExtensions.Contains(ext))
            return $"extensão '.{ext}' não permitida";

        // Tipo real por conteúdo (base Default do Mime-Detective).
        var detected = _inspector.Inspect(content).ByFileExtension();
        var topExt = detected.Length > 0 ? detected[0].Extension.ToLowerInvariant() : null;

        // 1) Tipo binário perigoso (executável etc.), independente da extensão.
        if (topExt is not null && DangerousTypes.Contains(topExt))
            return $"conteúdo identificado como tipo perigoso ('{topExt}')";

        // 2) Tipo real x extensão declarada — só para tipos com assinatura confiável
        //    (doc/xls/csv ficam de fora por serem OLE2/HTML/texto ambíguos).
        if (topExt is not null
            && TypeConsistency.TryGetValue(ext, out var acceptable)
            && !acceptable.Contains(topExt))
            return $"tipo real do conteúdo ('{topExt}') não confere com a extensão '.{ext}'";

        return null;
    }

    /// <summary>Tipo perigoso detectado por conteúdo (ex.: "exe"), ou null. Usado na inspeção de anexos embutidos.</summary>
    public string? DangerousContentType(byte[] content)
    {
        var detected = _inspector.Inspect(content).ByFileExtension();
        var topExt = detected.Length > 0 ? detected[0].Extension.ToLowerInvariant() : null;
        return topExt is not null && DangerousTypes.Contains(topExt) ? topExt : null;
    }

    internal bool IsPolicyCompatibleWith(FileScannerOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        return _opt.MaxFileSizeBytes == options.MaxFileSizeBytes
            && new HashSet<string>(_opt.AllowedExtensions, StringComparer.Ordinal)
                .SetEquals(options.AllowedExtensions);
    }

    // Tipos detectáveis por conteúdo que nunca devem ser aceitos como upload de usuário.
    private static readonly HashSet<string> DangerousTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        "exe", "dll", "sys", "scr", "com", "msi", "cpl", "ocx", "drv",
        "elf", "so", "dylib", "mach-o",
        "jar", "class", "apk", "dex",
        "bat", "cmd", "ps1", "vbs", "js", "wsf", "hta", "jse", "vbe",
    };

    // Para cada extensão "confiável", quais tipos detectados são aceitáveis.
    private static readonly Dictionary<string, HashSet<string>> TypeConsistency = new()
    {
        ["pdf"]  = new(StringComparer.OrdinalIgnoreCase) { "pdf" },
        ["jpg"]  = new(StringComparer.OrdinalIgnoreCase) { "jpg", "jpeg" },
        ["jpeg"] = new(StringComparer.OrdinalIgnoreCase) { "jpg", "jpeg" },
        ["png"]  = new(StringComparer.OrdinalIgnoreCase) { "png" },
        ["docx"] = new(StringComparer.OrdinalIgnoreCase) { "docx", "zip" },
        ["xlsx"] = new(StringComparer.OrdinalIgnoreCase) { "xlsx", "zip" },
    };
}
