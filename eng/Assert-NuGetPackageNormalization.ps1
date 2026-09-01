[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$normalizer = Join-Path $PSScriptRoot 'Normalize-NuGetPackage.ps1'
$tempBase = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { [IO.Path]::GetTempPath() }
$fixtureRoot = Join-Path $tempBase "filescan-package-normalization-$([Guid]::NewGuid().ToString('N'))"
$first = Join-Path $fixtureRoot 'first.nupkg'
$second = Join-Path $fixtureRoot 'second.nupkg'
$signed = Join-Path $fixtureRoot 'signed.nupkg'
$canonicalTimestamp = '2026-01-02T03:04:06Z'

Add-Type -AssemblyName System.IO.Compression
New-Item -ItemType Directory -Path $fixtureRoot > $null

function New-ZipFixture([string] $Path, [bool] $Reverse, [DateTimeOffset] $Timestamp,
    [bool] $IncludeSignature = $false) {
    $file = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite)
    try {
        $zip = [IO.Compression.ZipArchive]::new(
            $file, [IO.Compression.ZipArchiveMode]::Create, $false)
        try {
            $names = if ($Reverse) { @('b.txt', 'a.txt') } else { @('a.txt', 'b.txt') }
            foreach ($name in $names) {
                $entry = $zip.CreateEntry($name, [IO.Compression.CompressionLevel]::Optimal)
                $entry.LastWriteTime = $Timestamp
                $stream = $entry.Open()
                try {
                    $bytes = [Text.Encoding]::UTF8.GetBytes("conteudo-$name")
                    $stream.Write($bytes, 0, $bytes.Length)
                }
                finally { $stream.Dispose() }
            }
            if ($IncludeSignature) {
                $signature = $zip.CreateEntry('.signature.p7s')
                $signature.LastWriteTime = $Timestamp
                $stream = $signature.Open()
                try {
                    $bytes = [Text.Encoding]::UTF8.GetBytes('repository-signature-fixture')
                    $stream.Write($bytes, 0, $bytes.Length)
                }
                finally { $stream.Dispose() }
            }
        }
        finally { $zip.Dispose() }
    }
    finally { $file.Dispose() }
}

try {
    New-ZipFixture $first $false ([DateTimeOffset]'2024-01-02T03:04:06Z')
    New-ZipFixture $second $true ([DateTimeOffset]'2025-06-07T08:09:10Z')
    New-ZipFixture $signed $true ([DateTimeOffset]'2025-07-08T09:10:12Z') $true

    & $normalizer -PackagePath $first -TimestampUtc $canonicalTimestamp
    & $normalizer -PackagePath $second -TimestampUtc $canonicalTimestamp

    $firstHash = (Get-FileHash -LiteralPath $first -Algorithm SHA256).Hash
    $secondHash = (Get-FileHash -LiteralPath $second -Algorithm SHA256).Hash
    if ($firstHash -ne $secondHash) {
        throw "Normalização não foi canônica: first=$firstHash second=$secondHash"
    }

    & $normalizer -PackagePath $first -TimestampUtc $canonicalTimestamp
    $idempotentHash = (Get-FileHash -LiteralPath $first -Algorithm SHA256).Hash
    if ($idempotentHash -ne $firstHash) {
        throw "Normalização não foi idempotente: first=$firstHash repeat=$idempotentHash"
    }

    & $normalizer -PackagePath $first -TimestampUtc $canonicalTimestamp `
        -ExcludePackageSignature
    & $normalizer -PackagePath $signed -TimestampUtc $canonicalTimestamp `
        -ExcludePackageSignature
    $unsignedPayloadHash = (Get-FileHash -LiteralPath $first -Algorithm SHA256).Hash
    $signedPayloadHash = (Get-FileHash -LiteralPath $signed -Algorithm SHA256).Hash
    if ($signedPayloadHash -ne $unsignedPayloadHash) {
        throw "Assinatura de repositório alterou o payload canônico: unsigned=$unsignedPayloadHash signed=$signedPayloadHash"
    }

    Write-Host "Canário de pacote: normalização canônica/idempotente e comparação sem repository signature confirmadas ($firstHash)."
}
finally {
    Remove-Item -LiteralPath $fixtureRoot -Recurse -Force -ErrorAction SilentlyContinue
}
