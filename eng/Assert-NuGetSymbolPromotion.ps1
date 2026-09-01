[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $PackagePath,
    [Parameter(Mandatory)] [string] $SymbolPackagePath
)

$ErrorActionPreference = 'Stop'
$resolvedPackage = (Resolve-Path -LiteralPath $PackagePath).Path
$resolvedSymbols = (Resolve-Path -LiteralPath $SymbolPackagePath).Path
$tempBase = [IO.Path]::GetFullPath(
    $(if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { [IO.Path]::GetTempPath() }))
$probeRoot = [IO.Path]::GetFullPath(
    (Join-Path $tempBase "filescan-symbol-promotion-$([Guid]::NewGuid().ToString('N'))"))
if (-not $probeRoot.StartsWith($tempBase, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Diretório do canário de símbolos saiu da raiz temporária esperada.'
}
New-Item -ItemType Directory -Path $probeRoot > $null
$readyFile = Join-Path $probeRoot 'ready'
$packageUpload = Join-Path $probeRoot 'package-upload.bin'
$symbolUpload = Join-Path $probeRoot 'symbol-upload.bin'

$portProbe = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
$portProbe.Start()
$port = ([Net.IPEndPoint]$portProbe.LocalEndpoint).Port
$portProbe.Stop()

$serverJob = Start-Job -ArgumentList $port, $readyFile, $packageUpload, $symbolUpload -ScriptBlock {
    param($Port, $ReadyFile, $PackageUpload, $SymbolUpload)
    $ErrorActionPreference = 'Stop'

    function Write-Response([IO.Stream] $Stream, [int] $Status, [string] $ContentType,
        [byte[]] $Body) {
        $reason = if ($Status -eq 200) { 'OK' } else { 'Created' }
        $headers = [Text.Encoding]::ASCII.GetBytes(
            "HTTP/1.1 $Status $reason`r`nContent-Type: $ContentType`r`nContent-Length: $($Body.Length)`r`nConnection: close`r`n`r`n")
        $Stream.Write($headers, 0, $headers.Length)
        if ($Body.Length) { $Stream.Write($Body, 0, $Body.Length) }
        $Stream.Flush()
    }

    function Read-Line([IO.Stream] $Stream) {
        $bytes = [Collections.Generic.List[byte]]::new()
        while ($true) {
            $value = $Stream.ReadByte()
            if ($value -lt 0) { throw 'Conexão HTTP terminou durante linha chunked.' }
            if ($value -eq 10) { break }
            if ($value -ne 13) { $bytes.Add([byte]$value) }
        }
        return [Text.Encoding]::ASCII.GetString($bytes.ToArray())
    }

    function Copy-Exactly([IO.Stream] $NetworkStream, [IO.Stream] $OutputStream, [long] $Length) {
        $buffer = [byte[]]::new(81920)
        $remaining = $Length
        while ($remaining -gt 0) {
            $read = $NetworkStream.Read($buffer, 0, [int][Math]::Min($buffer.Length, $remaining))
            if ($read -le 0) { throw 'Conexão HTTP terminou antes do corpo declarado.' }
            $OutputStream.Write($buffer, 0, $read)
            $remaining -= $read
        }
    }

    function Read-Body([IO.Stream] $NetworkStream, [hashtable] $Headers, [string] $Destination) {
        $output = [IO.File]::Open($Destination, [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write, [IO.FileShare]::None)
        try {
            if ($Headers['transfer-encoding'] -match 'chunked') {
                while ($true) {
                    $line = Read-Line $NetworkStream
                    $sizeText = ($line -split ';', 2)[0]
                    $size = [Convert]::ToInt64($sizeText, 16)
                    if ($size -eq 0) {
                        while ((Read-Line $NetworkStream).Length -ne 0) { }
                        break
                    }
                    Copy-Exactly $NetworkStream $output $size
                    if ((Read-Line $NetworkStream).Length -ne 0) {
                        throw 'Separador chunked inválido.'
                    }
                }
                return
            }

            $length = if ($Headers.ContainsKey('content-length')) {
                [long]$Headers['content-length']
            } else { 0 }
            Copy-Exactly $NetworkStream $output $length
        }
        finally { $output.Dispose() }
    }

    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, $Port)
    $listener.Start()
    Set-Content -LiteralPath $ReadyFile -Value 'ready'
    $putCount = 0
    try {
        while ($putCount -lt 2) {
            $client = $listener.AcceptTcpClient()
            try {
                $stream = $client.GetStream()
                $headerBytes = [Collections.Generic.List[byte]]::new()
                while ($headerBytes.Count -lt 65536) {
                    $value = $stream.ReadByte()
                    if ($value -lt 0) { break }
                    $headerBytes.Add([byte]$value)
                    $count = $headerBytes.Count
                    if ($count -ge 4 -and
                        $headerBytes[$count - 4] -eq 13 -and $headerBytes[$count - 3] -eq 10 -and
                        $headerBytes[$count - 2] -eq 13 -and $headerBytes[$count - 1] -eq 10) { break }
                }

                $headerText = [Text.Encoding]::ASCII.GetString($headerBytes.ToArray())
                $lines = $headerText -split "`r`n"
                $request = $lines[0] -split ' '
                $method = $request[0]
                $path = $request[1]
                $route = $path.TrimEnd('/')
                $headers = @{}
                foreach ($line in $lines[1..($lines.Length - 1)]) {
                    $separator = $line.IndexOf(':')
                    if ($separator -gt 0) {
                        $key = $line.Substring(0, $separator).Trim().ToLowerInvariant()
                        $headers[$key] = $line.Substring($separator + 1).Trim()
                    }
                }

                if ($method -eq 'GET' -and $route -eq '/v3/index.json') {
                    $base = "http://127.0.0.1:$Port"
                    $json = "{`"version`":`"3.0.0`",`"resources`":[{`"@id`":`"$base/package`",`"@type`":`"PackagePublish/2.0.0`"},{`"@id`":`"$base/symbol`",`"@type`":`"SymbolPackagePublish/4.9.0`"}]}"
                    Write-Response $stream 200 'application/json' ([Text.Encoding]::UTF8.GetBytes($json))
                    continue
                }

                if ($method -eq 'PUT' -and $route -in @('/package', '/symbol')) {
                    if ($headers['expect'] -match '100-continue') {
                        $interim = [Text.Encoding]::ASCII.GetBytes("HTTP/1.1 100 Continue`r`n`r`n")
                        $stream.Write($interim, 0, $interim.Length)
                        $stream.Flush()
                    }
                    $destination = if ($route -eq '/package') { $PackageUpload } else { $SymbolUpload }
                    Read-Body $stream $headers $destination
                    Write-Response $stream 201 'text/plain' ([byte[]]::new(0))
                    $putCount++
                    continue
                }

                Write-Response $stream 200 'application/json' ([Text.Encoding]::UTF8.GetBytes('{}'))
            }
            finally { $client.Dispose() }
        }
    }
    finally { $listener.Stop() }
}

try {
    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    while (-not (Test-Path -LiteralPath $readyFile) -and [DateTime]::UtcNow -lt $deadline) {
        Start-Sleep -Milliseconds 50
    }
    if (-not (Test-Path -LiteralPath $readyFile)) {
        throw 'Feed V3 sintético não iniciou no prazo.'
    }

    $source = "http://127.0.0.1:$port/v3/index.json"
    & dotnet nuget push $resolvedPackage --source $source --api-key 'probe' `
        --no-symbols --allow-insecure-connections
    if ($LASTEXITCODE -ne 0) { throw 'Push sintético do pacote principal falhou.' }

    if (Test-Path -LiteralPath $symbolUpload) {
        throw '--no-symbols promoveu o snupkg junto com o pacote principal.'
    }

    & dotnet nuget push $resolvedSymbols --source $source --api-key 'probe' `
        --allow-insecure-connections
    if ($LASTEXITCODE -ne 0) { throw 'Push sintético explícito do pacote de símbolos falhou.' }

    $completed = Wait-Job -Job $serverJob -Timeout 15
    if (-not $completed) { throw 'Feed V3 sintético não recebeu os dois pacotes no prazo.' }
    Receive-Job -Job $serverJob

    function Get-UploadedPackageHash([string] $UploadPath, [long] $PackageLength) {
        $body = [IO.File]::ReadAllBytes($UploadPath)
        $start = -1
        for ($index = 0; $index -le $body.Length - 4; $index++) {
            if ($body[$index] -eq 0x50 -and $body[$index + 1] -eq 0x4B -and
                $body[$index + 2] -eq 0x03 -and $body[$index + 3] -eq 0x04) {
                $start = $index
                break
            }
        }
        if ($start -lt 0 -or $start + $PackageLength -gt $body.LongLength) {
            throw 'PUT multipart não contém um pacote ZIP completo.'
        }
        $packageBytes = [byte[]]::new($PackageLength)
        [Buffer]::BlockCopy($body, $start, $packageBytes, 0, $packageBytes.Length)
        return ConvertTo-HexString ([Security.Cryptography.SHA256]::HashData($packageBytes))
    }

    function ConvertTo-HexString([byte[]] $Bytes) {
        return [Convert]::ToHexString($Bytes)
    }

    $sourceMain = Get-Item -LiteralPath $resolvedPackage
    $sourceSymbols = Get-Item -LiteralPath $resolvedSymbols
    $sourceMainHash = (Get-FileHash -LiteralPath $resolvedPackage -Algorithm SHA256).Hash
    $uploadedMainHash = Get-UploadedPackageHash $packageUpload $sourceMain.Length
    $sourceSymbolHash = (Get-FileHash -LiteralPath $resolvedSymbols -Algorithm SHA256).Hash
    $uploadedSymbolHash = Get-UploadedPackageHash $symbolUpload $sourceSymbols.Length
    if ($sourceMainHash -ne $uploadedMainHash -or $sourceSymbolHash -ne $uploadedSymbolHash) {
        throw 'O feed V3 sintético não recebeu os bytes exatos dos dois pacotes.'
    }

    Write-Host "Canário de símbolos: nupkg isolado e snupkg explícito confirmados ($sourceSymbolHash)."
}
finally {
    if ($serverJob) {
        if ($serverJob.State -eq 'Failed') {
            Receive-Job -Job $serverJob -ErrorAction Continue
        }
        Remove-Job -Job $serverJob -Force -ErrorAction SilentlyContinue
    }
    Remove-Item -LiteralPath $probeRoot -Recurse -Force -ErrorAction SilentlyContinue
}
