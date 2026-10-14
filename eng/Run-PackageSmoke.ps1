[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $PackageDirectory,
    [string] $Version = '0.4.0'
)

$ErrorActionPreference = 'Stop'
$project = Join-Path $PSScriptRoot 'package-smoke/PackageSmoke.csproj'
$resolvedSource = (Resolve-Path -LiteralPath $PackageDirectory).Path

# Conteúdo do pacote: o worker TEM de estar dentro do nupkg (e não pode virar dependência do nuspec).
Add-Type -AssemblyName System.IO.Compression.FileSystem
$nupkg = Join-Path $resolvedSource "FileScan.Core.$Version.nupkg"
if (-not (Test-Path -LiteralPath $nupkg)) { throw "Pacote não encontrado: $nupkg" }
$zip = [IO.Compression.ZipFile]::OpenRead($nupkg)
try {
    $names = @($zip.Entries | ForEach-Object { $_.FullName })
    foreach ($required in @(
            'tools/filescan-worker/FileScan.Worker.dll',
            'tools/filescan-worker/FileScan.Worker.runtimeconfig.json',
            'tools/filescan-worker/FileScan.Worker.deps.json',
            'build/FileScan.Core.targets')) {
        if ($names -notcontains $required) { throw "Pacote sem '$required'." }
    }
    $nuspecEntry = $zip.Entries | Where-Object { $_.FullName -like '*.nuspec' } | Select-Object -First 1
    $reader = [IO.StreamReader]::new($nuspecEntry.Open())
    try { $nuspec = $reader.ReadToEnd() } finally { $reader.Dispose() }
    if ($nuspec -match 'FileScan\.Worker') { throw 'O nuspec não pode declarar dependência do FileScan.Worker.' }
}
finally { $zip.Dispose() }
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

    # `dotnet publish` do consumidor: o worker tem de acompanhar o publish e funcionar a partir dele.
    $publishDirectory = Join-Path $isolatedPackages 'publish'
    dotnet publish $project -c Release --no-build --no-restore -o $publishDirectory `
        -p:FileScanPackageVersion=$Version
    if ($LASTEXITCODE -ne 0) { throw 'Publish do package smoke falhou.' }
    foreach ($file in @('FileScan.Worker.dll', 'FileScan.Worker.runtimeconfig.json', 'FileScan.Worker.deps.json')) {
        if (-not (Test-Path -LiteralPath (Join-Path $publishDirectory "filescan-worker/$file"))) {
            throw "O publish do consumidor não contém filescan-worker/$file."
        }
    }
    dotnet (Join-Path $publishDirectory 'PackageSmoke.dll')
    if ($LASTEXITCODE -ne 0) { throw 'Execução do package smoke a partir do publish falhou.' }
}
finally {
    Remove-Item -LiteralPath $isolatedPackages -Recurse -Force -ErrorAction SilentlyContinue
}
