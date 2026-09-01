[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $PackageDirectory,
    [string] $Version = '0.2.0'
)

$ErrorActionPreference = 'Stop'
$project = Join-Path $PSScriptRoot 'package-smoke/PackageSmoke.csproj'
$resolvedSource = (Resolve-Path -LiteralPath $PackageDirectory).Path
$tempBase = [IO.Path]::GetFullPath(
    $(if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { [IO.Path]::GetTempPath() }))
$isolatedPackages = [IO.Path]::GetFullPath(
    (Join-Path $tempBase "filescan-package-smoke-$([Guid]::NewGuid().ToString('N'))"))
if (-not $isolatedPackages.StartsWith($tempBase, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Diretório temporário do package smoke saiu da raiz temporária esperada.'
}
New-Item -ItemType Directory -Path $isolatedPackages > $null
$configPath = Join-Path $isolatedPackages 'NuGet.Config'
$xmlSettings = [Xml.XmlWriterSettings]::new()
$xmlSettings.Indent = $true
$writer = [Xml.XmlWriter]::Create($configPath, $xmlSettings)
try {
    $writer.WriteStartDocument()
    $writer.WriteStartElement('configuration')
    $writer.WriteStartElement('packageSources')
    $writer.WriteStartElement('clear')
    $writer.WriteEndElement()
    $writer.WriteStartElement('add')
    $writer.WriteAttributeString('key', 'candidate')
    $writer.WriteAttributeString('value', $resolvedSource)
    $writer.WriteEndElement()
    $writer.WriteStartElement('add')
    $writer.WriteAttributeString('key', 'nuget.org')
    $writer.WriteAttributeString('value', 'https://api.nuget.org/v3/index.json')
    $writer.WriteAttributeString('protocolVersion', '3')
    $writer.WriteEndElement()
    $writer.WriteEndElement()
    $writer.WriteEndElement()
    $writer.WriteEndDocument()
}
finally { $writer.Dispose() }

try {
    $restoreArguments = @(
        'restore', $project,
        "-p:FileScanPackageVersion=$Version",
        '--configfile', $configPath,
        '--packages', $isolatedPackages,
        '--force-evaluate', '--no-http-cache', '--disable-build-servers'
    )
    & dotnet @restoreArguments
    if ($LASTEXITCODE -ne 0) { throw 'Restore do package smoke falhou.' }

    dotnet build $project -c Release --no-restore --disable-build-servers --no-incremental `
        -p:FileScanPackageVersion=$Version
    if ($LASTEXITCODE -ne 0) { throw 'Build não incremental do package smoke falhou.' }

    dotnet run --project $project -c Release --no-build --no-restore `
        -p:FileScanPackageVersion=$Version
    if ($LASTEXITCODE -ne 0) { throw 'Execução do package smoke falhou.' }
}
finally {
    Remove-Item -LiteralPath $isolatedPackages -Recurse -Force -ErrorAction SilentlyContinue
}
