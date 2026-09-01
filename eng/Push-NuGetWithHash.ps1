[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $PackagePath,
    [Parameter(Mandatory)] [string] $PackageId,
    [Parameter(Mandatory)] [string] $Version,
    [Parameter(Mandatory)] [string] $Source,
    [Parameter(Mandatory)] [string] $ApiKey,
    [string] $Username = '',
    [Parameter(Mandatory)] [string] $StateFile
)

$ErrorActionPreference = 'Stop'
$localHash = (Get-FileHash -LiteralPath $PackagePath -Algorithm SHA256).Hash.ToLowerInvariant()
$normalizer = Join-Path $PSScriptRoot 'Normalize-NuGetPackage.ps1'
$headers = @{}
if ($Username) {
    $pair = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${Username}:${ApiKey}"))
    $headers.Authorization = "Basic $pair"
}

function Get-ExistingPackage {
    $index = Invoke-RestMethod -Uri $Source -Headers $headers
    $base = $index.resources |
        Where-Object { $_.'@type' -like 'PackageBaseAddress*' } |
        Select-Object -First 1 -ExpandProperty '@id'
    if (-not $base) { throw "Fonte '$Source' não publicou PackageBaseAddress." }

    $id = $PackageId.ToLowerInvariant()
    $versionLower = $Version.ToLowerInvariant()
    $uri = "${base}${id}/${versionLower}/${id}.${versionLower}.nupkg"
    $tempRoot = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { [IO.Path]::GetTempPath() }
    $destination = Join-Path $tempRoot "existing-${id}-${versionLower}.nupkg"

    try {
        Invoke-WebRequest -Uri $uri -Headers $headers -OutFile $destination
        return $destination
    }
    catch {
        $status = $_.Exception.Response.StatusCode.value__
        if ($status -eq 404) { return $null }
        throw
    }
}

function Assert-SameExistingPackage([string] $ExistingPath) {
    $remoteHash = (Get-FileHash -LiteralPath $ExistingPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($remoteHash -eq $localHash) { return 'raw-hash' }

    # nuget.org adiciona uma repository signature (.signature.p7s) durante a ingestão. Para um
    # rerun, compara o payload canônico sem essa única entrada; nuspec, DLL, XML e qualquer outro
    # conteúdo continuam cobertos e uma divergência real permanece fatal.
    $tempRoot = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { [IO.Path]::GetTempPath() }
    $comparisonRoot = Join-Path $tempRoot "filescan-feed-compare-$([Guid]::NewGuid().ToString('N'))"
    New-Item -ItemType Directory -Path $comparisonRoot > $null
    try {
        $localCopy = Join-Path $comparisonRoot 'local.nupkg'
        $remoteCopy = Join-Path $comparisonRoot 'remote.nupkg'
        Copy-Item -LiteralPath $PackagePath -Destination $localCopy
        Copy-Item -LiteralPath $ExistingPath -Destination $remoteCopy
        $canonicalTimestamp = '1980-01-01T00:00:00Z'
        & $normalizer -PackagePath $localCopy -TimestampUtc $canonicalTimestamp `
            -ExcludePackageSignature
        & $normalizer -PackagePath $remoteCopy -TimestampUtc $canonicalTimestamp `
            -ExcludePackageSignature
        $localPayloadHash = (Get-FileHash -LiteralPath $localCopy -Algorithm SHA256).Hash.ToLowerInvariant()
        $remotePayloadHash = (Get-FileHash -LiteralPath $remoteCopy -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($remotePayloadHash -ne $localPayloadHash) {
            throw "A versão $PackageId $Version já existe em $Source com payload divergente: localRaw=$localHash remotoRaw=$remoteHash localPayload=$localPayloadHash remotoPayload=$remotePayloadHash"
        }
        Write-Host "Hash bruto remoto difere por metadado de assinatura, mas o payload canônico coincide ($localPayloadHash)."
        return 'canonical-payload'
    }
    finally {
        Remove-Item -LiteralPath $comparisonRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

$existing = Get-ExistingPackage
if ($existing) {
    try { $match = Assert-SameExistingPackage $existing }
    finally { Remove-Item -LiteralPath $existing -Force -ErrorAction SilentlyContinue }
    Set-Content -LiteralPath $StateFile -Value "already-present-$match $localHash"
    Write-Host "Pacote já existente corresponde por $match; promoção idempotente confirmada."
    exit 0
}

$pushOutput = & dotnet nuget push $PackagePath --source $Source --api-key $ApiKey --no-symbols 2>&1 | Out-String
if ($LASTEXITCODE -eq 0) {
    Set-Content -LiteralPath $StateFile -Value "published $localHash"
    Write-Host $pushOutput
    exit 0
}

# Fecha a janela de corrida: se outro job publicou entre o GET e o push, só aceita o mesmo hash.
$existingAfterRace = Get-ExistingPackage
if ($existingAfterRace) {
    try { $match = Assert-SameExistingPackage $existingAfterRace }
    finally { Remove-Item -LiteralPath $existingAfterRace -Force -ErrorAction SilentlyContinue }
    Set-Content -LiteralPath $StateFile -Value "race-$match $localHash"
    exit 0
}

throw "Push para $Source falhou e nenhum pacote verificável apareceu. Saída:`n$pushOutput"
