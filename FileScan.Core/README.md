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
    // Per-stream + aggregate decompression/entry/depth budgets are per instance.
});

ScanResponse result = await scanner.ScanAsync(fileName, bytes);
if (result.Verdict != ScanVerdict.Clean)
    Reject(result.Reason); // Rejected: reason says exactly what was found
```

Options are copied into a validated **per-instance snapshot** (no global or caller-mutable state):
two consumers can use different limits, and later mutations of the original options object cannot
alter an existing scanner.

## What it checks

1. **Structural** (cheap, synchronous): size, extension allowlist, and **real content type via
   magic bytes** (Mime-Detective) — rejects dangerous binaries (a disguised `.exe`) and files
   whose content doesn't match the declared extension.
2. **Active content** (multi-format heuristics):
   - **PDF**: structural parsing of xref/trailer, indirect references and object streams; JavaScript
     (`/JavaScript`, `/JS`), `/Launch`, and recursive embedded attachments resolved through
     normative `FileSpec` associations (`EmbeddedFiles` under the root catalog's `Names`, `AF`
     on PDF objects, and `FS` inside `FileAttachment` annotations) and `/EF` share bounded
     work/depth budgets (`/Type /EmbeddedFile` is optional; unrelated `/EmbeddedFiles`, `/EF`,
     and `/FS` keys are ignored; malformed, unsorted, or incoherent name trees fail closed;
     `/Kids` must use indirect references, the root must not declare `/Limits`, and every non-root
     node must declare coherent `/Limits`; literal and hexadecimal string keys share decoded-byte
     ordering and equality).
     Unsupported filters/predictors, encryption and ambiguous structures return
     `NotInspected`; hex-encoded names (`/J#53` ≡ `/JS`) are normalized.
   - **Office OOXML** (`docx`/`xlsx`): DDE, VBA macros, formula injection, embedded OLE objects.
   - **CSV**: formula/command injection per OWASP.
   - **Images** (`jpg`/`png`/`gif`): embedded `<script>`/`<?php`.
   - **Legacy/HTML** (`doc`/`xls`): scripts, DDE, macro markers.
3. **Antivirus integration** (optional, pluggable): consumers may implement `IVirusScanner` to
   add an engine. The package has no antivirus-engine or daemon dependency; without this optional
   integration, the structural + active-content layers run on their own.

Policy is configurable (`OnActiveContent`): `Reject` (default), `Flag` (returns the non-persistable
`ActiveContentDetected` verdict plus `Warnings`), or `Ignore` (returns `NotInspected` because the
inspection was skipped). The only persistence rule is `Verdict == Clean`.

`Clean` implies no findings, no warnings, no skipped inspection and no exhausted/ambiguous limit.
An optional antivirus `Clean` result cannot promote an incomplete structural result; the final
verdict remains `NotInspected` and is attributed to `filescan`.
Cancellation is propagated through upload materialization, PDF/OOXML parsing, decompression and
attachment recursion; it is never converted into `Clean` or `NotInspected`.

## Scope

FileScan.Core does **heuristic detection** of malicious/active content. It is **not** a certified
CDR product and does not replace a full antivirus — use it as a **defense-in-depth layer** and
validate in your own context. Encrypted/obfuscated payloads and zero-day threats may evade it.
See the repository's `SECURITY.md` for known evasions/limitations and caller responsibilities
when serving uploaded files.

## License

MIT — see the repository's `LICENSE`.
