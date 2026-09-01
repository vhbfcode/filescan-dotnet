[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $PackagePath,
    [Parameter(Mandatory)] [string] $TimestampUtc,
    [switch] $ExcludePackageSignature
)

$ErrorActionPreference = 'Stop'
$resolved = (Resolve-Path -LiteralPath $PackagePath).Path
$timestamp = [DateTimeOffset]::Parse(
    $TimestampUtc,
    [Globalization.CultureInfo]::InvariantCulture,
    [Globalization.DateTimeStyles]::AssumeUniversal).ToUniversalTime()

# ZIP armazena datas entre 1980 e 2107, com precisão de dois segundos.
if ($timestamp.Year -lt 1980 -or $timestamp.Year -gt 2107) {
    throw "Timestamp '$TimestampUtc' está fora do intervalo representável por ZIP."
}
$timestamp = [DateTimeOffset]::new(
    $timestamp.Year, $timestamp.Month, $timestamp.Day,
    $timestamp.Hour, $timestamp.Minute, $timestamp.Second - ($timestamp.Second % 2),
    [TimeSpan]::Zero)

Add-Type -AssemblyName System.IO.Compression
$temporary = "$resolved.normalizing"
Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue

try {
    $inputFile = [IO.File]::Open($resolved, [IO.FileMode]::Open,
        [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $inputZip = [IO.Compression.ZipArchive]::new(
            $inputFile, [IO.Compression.ZipArchiveMode]::Read, $false)
        try {
            $outputFile = [IO.File]::Open($temporary, [IO.FileMode]::CreateNew,
                [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
            try {
                $outputZip = [IO.Compression.ZipArchive]::new(
                    $outputFile, [IO.Compression.ZipArchiveMode]::Create, $false)
                try {
                    $entries = @($inputZip.Entries |
                        Where-Object {
                            -not $ExcludePackageSignature -or
                            $_.FullName -cne '.signature.p7s'
                        } |
                        Sort-Object FullName)
                    $duplicates = @($entries | Group-Object FullName | Where-Object Count -gt 1)
                    if ($duplicates.Count) {
                        throw "Pacote contém entradas ZIP duplicadas: $($duplicates.Name -join ', ')"
                    }

                    foreach ($entry in $entries) {
                        $normalized = $outputZip.CreateEntry(
                            $entry.FullName, [IO.Compression.CompressionLevel]::Optimal)
                        $normalized.LastWriteTime = $timestamp
                        $normalized.ExternalAttributes = 0

                        if (-not $entry.FullName.EndsWith('/', [StringComparison]::Ordinal)) {
                            $source = $entry.Open()
                            try {
                                $destination = $normalized.Open()
                                try { $source.CopyTo($destination) }
                                finally { $destination.Dispose() }
                            }
                            finally { $source.Dispose() }
                        }
                    }
                }
                finally { $outputZip.Dispose() }
            }
            finally { $outputFile.Dispose() }
        }
        finally { $inputZip.Dispose() }
    }
    finally { $inputFile.Dispose() }

    Move-Item -LiteralPath $temporary -Destination $resolved -Force
}
finally {
    Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
}

Write-Host "Pacote normalizado deterministicamente: $resolved @ $($timestamp.ToString('O'))"
