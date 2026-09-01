[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$unavailableConfig = Join-Path $PSScriptRoot 'audit-fixtures/UnavailableAuditSource.NuGet.config'
$vulnerableProject = Join-Path $PSScriptRoot 'audit-fixtures/VulnerableTransitive/VulnerableTransitive.csproj'
$criticalProject = Join-Path $PSScriptRoot 'audit-fixtures/VulnerableCritical/VulnerableCritical.csproj'
$coreProject = Join-Path $repo 'FileScan.Core/FileScan.Core.csproj'

function Assert-ExpectedRestoreFailure {
    param(
        [Parameter(Mandatory)] [string] $ExpectedCode,
        [Parameter(Mandatory)] [string[]] $Arguments
    )

    $output = & dotnet @Arguments 2>&1 | Out-String
    $exitCode = $LASTEXITCODE
    if ($exitCode -eq 0) {
        throw "Restore-canary deveria falhar com $ExpectedCode, mas terminou com exit code 0."
    }
    if ($output -notmatch [regex]::Escape($ExpectedCode)) {
        throw "Restore-canary falhou sem produzir $ExpectedCode. Saída:`n$output"
    }
    Write-Host "Canário ${ExpectedCode}: falha fechada confirmada."
}

Assert-ExpectedRestoreFailure -ExpectedCode 'NU1900' -Arguments @(
    'restore', $coreProject,
    '--configfile', $unavailableConfig,
    '--force-evaluate', '--no-http-cache', '--disable-build-servers', '-v:minimal'
)

Assert-ExpectedRestoreFailure -ExpectedCode 'NU1903' -Arguments @(
    'restore', $vulnerableProject,
    '--force-evaluate', '--no-http-cache', '--disable-build-servers', '-v:minimal'
)

Assert-ExpectedRestoreFailure -ExpectedCode 'NU1904' -Arguments @(
    'restore', $criticalProject,
    '--force-evaluate', '--no-http-cache', '--disable-build-servers', '-v:minimal'
)
