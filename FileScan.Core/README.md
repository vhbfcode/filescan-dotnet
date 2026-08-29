# FileScan.Core

Upload **file validation for .NET** — in-process, no API call, no antivirus daemon required.

Most upload pipelines trust the file extension. Malicious uploads — PDFs with auto-executing
JavaScript, Office documents with DDE/macros, CSV formula injection, polyglot images — pass an
extension check, and pass signature-based antivirus when the payload is new. FileScan.Core catches
this class of attack at the **application layer**, before the file reaches storage.

> Documentação em português: veja o
> [repositório no GitHub](https://github.com/vhbfcode/filescan-dotnet).

## Usage

```csharp
using FileScan.Scanning;

var scanner = new FileScanService(new FileScannerOptions
{
    AllowedExtensions = ["pdf", "docx", "xlsx", "csv", "jpg", "png"],
    // MaxFileSizeBytes / MaxDecompressedBytesPerStream / OnActiveContent — per-instance options
});

ScanResponse result = await scanner.ScanAsync(fileName, bytes);
if (result.Verdict != ScanVerdict.Clean)
    Reject(result.Reason); // Rejected: reason says exactly what was found
```

Options are **per instance** (no global state): two consumers in the same process can use
different limits.

## What it checks

1. **Structural** (cheap, synchronous): size, extension allowlist, and **real content type via
   magic bytes** (Mime-Detective) — rejects dangerous binaries (a disguised `.exe`) and files
   whose content doesn't match the declared extension.
2. **Active content** (multi-format heuristics):
   - **PDF**: JavaScript (`/JavaScript`, `/JS`), `/Launch`, recursive inspection of embedded
     attachments; streams are always decompressed before being judged (compressed bytes are never
     scanned raw — no random-data false positives), and hex-encoded names (`/J#53` ≡ `/JS`) are
     normalized so they can't evade detection.
   - **Office OOXML** (`docx`/`xlsx`): DDE, VBA macros, formula injection, embedded OLE objects.
   - **CSV**: formula/command injection per OWASP.
   - **Images** (`jpg`/`png`/`gif`): embedded `<script>`/`<?php`.
   - **Legacy/HTML** (`doc`/`xls`): scripts, DDE, macro markers.
3. **Antivirus** (optional, pluggable): implement `IVirusScanner` to add an engine. The
   [FileScan API](https://github.com/vhbfcode/filescan-dotnet) plugs ClamAV in this way; without
   one, the structural + active-content layers run on their own.

Policy is configurable (`OnActiveContent`): `Reject` (default), `Flag` (pass with `Warnings`),
or `Ignore`.

## Scope

FileScan.Core does **heuristic detection** of malicious/active content. It is **not** a certified
CDR product and does not replace a full antivirus — use it as a **defense-in-depth layer** and
validate in your own context. Encrypted/obfuscated payloads and zero-day threats may evade it.
See the repository's `SECURITY.md` for known evasions/limitations and caller responsibilities
when serving uploaded files.

## License

MIT — see the repository's `LICENSE`.
