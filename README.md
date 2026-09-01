**English** · [Português](README.pt-BR.md)

# FileScan

![.NET](https://img.shields.io/badge/.NET-10-512BD4) ![License](https://img.shields.io/badge/license-MIT-blue) ![Tests](https://img.shields.io/badge/tests-145%20passing-brightgreen)

A small **file-validation microservice**: hand it an uploaded file and it returns a fail-closed
persistence verdict — designed to sit in front of existing apps with a single HTTP call before the
file reaches storage. `Clean` is a bounded structural/active-content result, not a malware certificate.

Most upload pipelines trust the file extension. Malicious uploads — PDFs with auto-running
JavaScript, Office documents with DDE/macros, CSV formula injection, polyglot images — slip past
extension checks, and past signature-based antivirus when the payload is new. FileScan catches that
class of attack at the **application layer**, before the file is stored. It also fills a real gap:
there is no widely-used free **.NET** library for multi-format injection detection — the
alternatives are commercial CDR products or language-specific tools.

## Highlights

- **Multi-format injection detection** — PDF JavaScript, Office DDE/macros, CSV formula injection
  (OWASP), polyglot images — plus **recursive inspection of PDF attachments** (a benign embedded XML
  passes; an embedded `.exe` is caught).
- **True file-type checking** by content / magic bytes (Mime-Detective), not just the extension.
- **Reusable as a library** — the scanning engine is a standalone class library (`FileScan.Core`):
  reference it directly from any .NET app, no API call and no ClamAV needed.
- **No container required** — the ClamAV antivirus layer is optional; with it off, the service is
  pure .NET and deploys like any ordinary web app.
- **Validated on real documents — zero false positives** — dozens of real-world files (insurance
  PDFs, Office documents, images) pass cleanly after false-positive tuning.
- **Security-minded** — fail-closed semantics, per-client rate limiting on by default, Swagger gated
  to Development, optional constant-time API-key auth, configurable size/decompression limits.
- **145 automated tests** (xUnit) with inputs generated in code — `dotnet test`, no Docker needed.

> ⚠️ **Notice / Scope:** FileScan performs **heuristic detection** of malicious / script-injection
> content. It is **not** a certified CDR product, it does **not** replace a full antivirus or a
> commercial solution, and it is provided **without warranty** (see [LICENSE](LICENSE)). Use it as a
> **defense-in-depth layer** and validate it in your own context — obfuscated/encrypted payloads and
> zero-day threats may evade it. See [SECURITY.md](SECURITY.md).

## How it works

Three validation layers, in order:

1. **Structural** (cheap, synchronous): size, **extension allowlist**, and **real content type via
   Mime-Detective** (magic bytes) — rejects dangerous binaries (a disguised `.exe`) and files whose
   content doesn't match the declared extension (e.g. a PNG renamed to `.pdf`).
2. **Active content** (multi-format heuristics): detects script injection per file type —
   - **PDF**: an Apache-2.0 structural parser validates xref/trailer, indirect references and object
     streams; JavaScript (`/JavaScript`, `/JS`), `/Launch`, and attachments are inspected recursively
     with shared depth/entry/decompression budgets. Unsupported filters, predictors, encryption or
     ambiguous structures return `NotInspected`. Hex-encoded names (`/J#53` ≡ `/JS`) are normalized.
   - **Office OOXML** (`docx`/`xlsx`): unzips and looks for DDE, macros (`vbaProject`), formula
     injection, and OLE objects.
   - **CSV**: formula/command injection per **OWASP** (cell starting with `=` `@` Tab, or `+`/`-`
     when it looks like a formula; `cmd|`, `WEBSERVICE`…).
   - **Images** (`jpg`/`png`): embedded `<script>`/`<?php` markers (best effort).
   - **Legacy/HTML** (`doc`/`xls`): `<script>`, DDE, formulas, and macro markers.
3. **Antivirus** (optional): scan via **ClamAV** (open-source engine) using the `nClam` client.

> The active-content layer **detects and applies a policy — it does not sanitize** (not CDR).
> Encrypted/obfuscated payloads may evade it; full coverage requires CDR or a sandbox.

> **ClamAV is optional** (`FileScan:ClamAv:Enabled`): when disabled, the service runs only the
> structural + active-content layers — **no container/daemon required**.

---

## Use as a library (`FileScan.Core`)

The scanning engine lives in **`FileScan.Core`**, a plain class library using Mime-Detective and
PdfPig — no ClamAV, no ASP.NET, no daemon. Any .NET project can reference it and validate
uploads in-process, without calling an API:

```csharp
using FileScan.Scanning;

var scanner = new FileScanService(new FileScannerOptions
{
    AllowedExtensions = ["pdf", "docx", "xlsx", "csv", "jpg", "png"],
    // Per-stream + aggregate decompression/entry/depth budgets are per instance.
});

ScanResponse result = await scanner.ScanAsync(fileName, bytes);
if (result.Verdict != ScanVerdict.Clean)
    // reject the upload (result.Reason says why)
```

Options are **snapshotted per instance** (no global or caller-mutable state): two consumers in the
same process can use different limits, and mutating the original `FileScannerOptions` after
construction does not change an existing scanner. An antivirus engine can be plugged in via the
optional `IVirusScanner` interface — that is exactly how this repo's API plugs ClamAV in.

To produce the NuGet package locally: `dotnet pack FileScan.Core -c Release -o artifacts`.

Releases are published by tagging (`git tag v0.2.0 && git push origin v0.2.0`) to
**[nuget.org](https://www.nuget.org/packages/FileScan.Core)** (via Trusted Publishing / OIDC —
no long-lived keys) and to **GitHub Packages**. Before hashing, package ZIP timestamps are
normalized to the commit timestamp, so a retry of the same tag recreates the same artifact rather
than masking or inventing a hash divergence. On nuget.org reruns, only the repository-added
`.signature.p7s` entry is excluded from the canonical payload comparison; every distributed file
remains hash-covered. Consuming from nuget.org needs no setup:

The workflow publishes the deterministic `.snupkg` explicitly to nuget.org's symbol server and
records its own SHA-256. GitHub Packages is the package mirror (`.nupkg`); it is not treated as a
symbol server.

```bash
dotnet add package FileScan.Core
```

GitHub Packages (`https://nuget.pkg.github.com/vhbfcode/index.json`) remains as a mirror; it
requires authentication even for public packages (PAT with `read:packages`).

---

## API

### `POST /scan`
- **Request:** `multipart/form-data`, file in the `file` field.
- **Auth:** `X-Api-Key` header (only when `FileScan:ApiKey` is configured).
- **Response 200** (final verdict):
  ```json
  {
    "fileName": "contract.pdf",
    "sizeBytes": 18342,
    "verdict": "Clean",        // Clean | Malicious | Rejected | NotInspected | ActiveContentDetected
    "reason": null,            // populated when not Clean
    "engine": "clamav",        // "clamav" or "filescan" (which layer decided)
    "scannedAtUtc": "2026-05-29T13:00:00.0000000Z"
  }
  ```
- **Response 503**: `verdict = "Error"` — the file could not be scanned (ClamAV down). The caller
  **must fail closed**. (Only happens when `ClamAv:Enabled=true`.)

**Verdict contract (fail-closed by design):** `Clean` means the structural/active-content
inspection **completed in full** and found nothing. When part of the file could not be inspected —
unsupported stream filter, encrypted PDF, invalid/truncated structure, decompression limit hit —
the verdict is **`NotInspected`** (never `Clean`): absence of inspection is not acceptance, and the
absence of an antivirus engine does not change that.

`Flag` returns `ActiveContentDetected` with `warnings`; `Ignore` returns `NotInspected` because the
inspection was skipped. Neither policy can return `Clean`. If the antivirus says `Clean` while the
structural layer is incomplete, the final result remains `NotInspected` with `engine = "filescan"`.
PDF attachments are resolved from normative `FileSpec` associations (`EmbeddedFiles`, `AF`, and
`FS` inside a `/Subtype /FileAttachment` annotation) and their `/EF` relation; `/Type
/EmbeddedFile` is not required. Unrelated `/EF` or `/FS` extension keys are not treated as
attachments. Invalid name-tree values, `/Limits` on the root name-tree node, and missing, cyclic
or non-stream associated targets return `NotInspected`. Literal and hexadecimal PDF strings are
ordered and compared by their decoded bytes, including child `/Limits`. Cancellation is propagated as `OperationCanceledException`, including between
upload materialization and parsing.

> ⚠️ **Scope of that guarantee: PDF and OOXML.** Only those inspectors can tell "inspected in
> full" apart from "couldn't read this part". For legacy OLE2 (`.doc`/`.xls`), images, CSV and
> text the engine is a best-effort byte-scanning heuristic: `Clean` there means "no marker
> matched", **not** "fully parsed" (an obfuscated/compressed OLE2 macro can evade it). If you
> accept OLE2 uploads without an antivirus engine plugged in, treat that as a residual risk —
> or block those extensions via `AllowedExtensions`.

**Caller's golden rule:** only persist the file if `HTTP 200` **and** `verdict == "Clean"`.

> ⚠️ **`Clean` ≠ "safe to render inline".** FileScan only scans; it never serves files.
> When you serve a user upload to a browser, the consuming app **must** serve it as a
> download (`Content-Disposition: attachment`), disable sniffing (`X-Content-Type-Options: nosniff`),
> send the correct `Content-Type`, and apply a CSP (`object-src 'none'`) — ideally from a
> separate, cookie-less origin. That is what neutralizes stored XSS via JavaScript-bearing
> PDFs. See [SECURITY.md](SECURITY.md#caller-responsibilities-serving-uploaded-files).

### `GET /health`
Liveness — the process is up.

### `GET /ready`
Readiness — ClamAV answers a ping (`200`) or not (`503`). Always `200` when ClamAV is disabled.

Interactive docs (Swagger UI) are served at `/swagger`.

---

## Configuration (`appsettings.json` → `FileScan` section)

| Key | Default | Description |
|---|---|---|
| `MaxFileSizeBytes` | `26214400` (25 MB) | Maximum accepted file size (also drives the request body limit, plus a small margin) |
| `MaxDecompressedBytesPerStream` | `16777216` (16 MB) | Per-stream/attachment cap on decompressed bytes (zip-bomb guard) |
| `MaxTotalDecompressedBytes` | `67108864` (64 MB) | Aggregate expansion budget shared by PDF, OOXML and recursive attachments |
| `MaxContainerEntries` | `1024` | Aggregate object/stream/container-entry budget per scan |
| `MaxEmbeddedFiles` / `MaxEmbeddedDepth` | `50` / `3` | Aggregate attachment count and recursive PDF depth limits |
| `AllowedExtensions` | `pdf,doc,docx,xls,xlsx,csv,jpg,jpeg,png` | Accepted extension allowlist; empty = no restriction |
| `ApiKey` | `""` | Requires the `X-Api-Key` header when set |
| `ClamAv:Enabled` | `true` | Enables the antivirus layer. `false` = structural + active-content only (**no container/daemon**) |
| `ClamAv:Host` / `ClamAv:Port` | `localhost` / `3310` | Address of the `clamd` daemon (when enabled) |
| `ActiveContent:OnDetected` | `Reject` | `Reject`; `Flag` → `ActiveContentDetected` + warnings; `Ignore` → `NotInspected` |
| `RateLimit:Enabled` / `:PermitLimit` / `:WindowSeconds` | `true` / `60` / `60` | Rate limit on `/scan` per client (API key, else IP): N requests per window → `429` |

Any key can be overridden by environment variables, e.g. `FileScan__ClamAv__Enabled=false`.

---

## Quick start

Without ClamAV (structural + active-content only — no Docker):

```bash
FileScan__ClamAv__Enabled=false dotnet run --project FileScan.Api
# then open http://localhost:5080/swagger
```

With the full antivirus layer:

```bash
docker run -d --name clamav -p 3310:3310 clamav/clamav   # wait until "healthy"
dotnet run --project FileScan.Api
```

---

## Integration example (caller side)

```csharp
using var content = new MultipartFormDataContent();
content.Add(new StreamContent(file.OpenReadStream()), "file", file.FileName);

var resp = await httpClient.PostAsync("https://filescan.../scan", content, ct);
if (resp.StatusCode != HttpStatusCode.OK)
    throw new InvalidOperationException("Validation unavailable — upload refused."); // fail closed

var result = await resp.Content.ReadFromJsonAsync<ScanResponse>(cancellationToken: ct);
if (result!.Verdict != "Clean")
    throw new InvalidOperationException($"File refused: {result.Reason}");

// only here do you write to storage
```

---

## Tests

```bash
dotnet test
```

Automated xUnit suite: per-format inspection + end-to-end tests against the `/scan` endpoint
(with ClamAV **disabled**, so no Docker is needed). Test inputs are generated in code — no external
files. There are also manual helper scripts under `_testfiles/` (`run_pdf_batch.py <folder>`,
`make-injections.ps1`).

## License

[MIT](LICENSE) © 2026 Vitor Fallavena.

Dependencies: **nClam** (Apache-2.0), **PdfPig** (Apache-2.0), **Mime-Detective** (MIT; *Default* definitions free for
commercial use), **Serilog** (Apache-2.0), **Swashbuckle** (MIT). **ClamAV** (GPLv2) runs as a
**separate** process/container — it is not linked into this project's code.

## Acknowledgments

Designed and built with [Claude Code](https://www.anthropic.com/claude-code) — from the initial
analysis through the multi-format detection, false-positive tuning on real documents, security
hardening, and tests.
