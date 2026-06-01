# Gera arquivos de teste com injeção de script para cada extensão aceita pelo cliente.
# Payloads são PoC benignos (alert/calc/echo) — representam o vetor sem dano real.
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression | Out-Null
Add-Type -AssemblyName System.IO.Compression.FileSystem | Out-Null

$dir = 'C:\Users\vitor\source\FileScan\_testfiles\injections'
New-Item -ItemType Directory -Force -Path $dir | Out-Null

$JS  = "<script>alert('XSS')</script>"
$PHP = "<?php echo('INJECTED'); ?>"
$DDE = 'DDEAUTO c:\Windows\System32\cmd.exe "/c calc.exe"'
$FX  = "=cmd|'/c calc.exe'!A1"

function Write-Text($name, $text) {
  [System.IO.File]::WriteAllText((Join-Path $dir $name), $text, [System.Text.Encoding]::ASCII)
}
function Write-Bytes($name, [byte[]]$bytes) {
  [System.IO.File]::WriteAllBytes((Join-Path $dir $name), $bytes)
}
function New-Zip($name, [hashtable]$entries) {
  $path = Join-Path $dir $name
  if (Test-Path $path) { Remove-Item $path -Force }
  $fs = [System.IO.File]::Open($path, 'CreateNew')
  $zip = New-Object System.IO.Compression.ZipArchive($fs, 'Create')
  foreach ($k in $entries.Keys) {
    $e = $zip.CreateEntry($k)
    $sw = New-Object System.IO.StreamWriter($e.Open())
    $sw.Write($entries[$k]); $sw.Dispose()
  }
  $zip.Dispose(); $fs.Dispose()
}

# --- PDF: JavaScript em /OpenAction ---
$pdf = @'
%PDF-1.3
1 0 obj
<</Type /Catalog /Pages 2 0 R /OpenAction <</S /JavaScript /JS (app.alert\('XSS'\)) >> >>
endobj
2 0 obj
<</Type /Pages /Count 1 /Kids [3 0 R]>>
endobj
3 0 obj
<</Type /Page /Parent 2 0 R /MediaBox [0 0 612 792]>>
endobj
trailer
<</Root 1 0 R>>
%%EOF
'@
Write-Text 'injection.pdf' $pdf

# --- CSV: formula/command injection ---
$csv = "Nome,Valor`r`n$FX,a`r`n@SUM(1+1)*cmd|'/c calc'!A1,b`r`n+1+1,c`r`n=HYPERLINK(`"http://evil.example/x`",`"clique`"),d`r`n"
Write-Text 'injection.csv' $csv

# --- DOCX (OOXML/zip): DDE no document.xml ---
$ctDoc = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>'
$relsDoc = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>'
$document = '<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:fldChar w:fldCharType="begin"/></w:r><w:r><w:instrText xml:space="preserve"> ' + $DDE + ' </w:instrText></w:r><w:r><w:fldChar w:fldCharType="end"/></w:r></w:p></w:body></w:document>'
New-Zip 'injection.docx' @{ '[Content_Types].xml' = $ctDoc; '_rels/.rels' = $relsDoc; 'word/document.xml' = $document }

# --- XLSX (OOXML/zip): formula injection na planilha ---
$ctXls = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>'
$relsXls = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>'
$workbook = '<?xml version="1.0"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="S1" sheetId="1" r:id="rId1"/></sheets></workbook>'
$wbRels = '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>'
$sheet = '<?xml version="1.0"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData><row r="1"><c r="A1" t="str"><f>cmd|''/c calc.exe''!A1</f><v>x</v></c></row></sheetData></worksheet>'
New-Zip 'injection.xlsx' @{ '[Content_Types].xml' = $ctXls; '_rels/.rels' = $relsXls; 'xl/workbook.xml' = $workbook; 'xl/_rels/workbook.xml.rels' = $wbRels; 'xl/worksheets/sheet1.xml' = $sheet }

# --- DOC (legado): HTML com <script> renomeado .doc (Word abre) ---
Write-Text 'injection.doc' ('<html xmlns:o="urn:schemas-microsoft-com:office:office"><body><p>' + $JS + '</p><!-- ' + $DDE + ' --></body></html>')

# --- XLS (legado): HTML com formula renomeado .xls (Excel abre) ---
Write-Text 'injection.xls' ('<html><body><table><tr><td>' + $FX + '</td></tr><tr><td>' + $JS + '</td></tr></table></body></html>')

# --- PNG: assinatura PNG + script em chunk de texto + PHP anexado ---
$pngSig = [byte[]](0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A)
$pngBody = [System.Text.Encoding]::ASCII.GetBytes("IHDR....tEXtComment`0$JS  IEND  $PHP")
Write-Bytes 'injection.png' ([byte[]]($pngSig + $pngBody))

# --- JPG: assinatura JPEG + segmento COM com <script> + PHP anexado ---
$com = [System.Text.Encoding]::ASCII.GetBytes($JS)
$len = $com.Length + 2
$jpgHead = [byte[]](0xFF,0xD8, 0xFF,0xFE, [byte](($len -shr 8) -band 0xFF), [byte]($len -band 0xFF))
$jpgTail = [byte[]](0xFF,0xD9)
$phpBytes = [System.Text.Encoding]::ASCII.GetBytes($PHP)
Write-Bytes 'injection.jpg' ([byte[]]($jpgHead + $com + $jpgTail + $phpBytes))
Copy-Item (Join-Path $dir 'injection.jpg') (Join-Path $dir 'injection.jpeg') -Force

Get-ChildItem $dir | Sort-Object Name | Select-Object Name, Length | Format-Table -AutoSize
