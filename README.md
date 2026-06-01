**English** · [Português](README.pt-BR.md)

# FileScan

A small **file-validation microservice**. It takes an uploaded file and tells you whether it is
**malicious or not** — designed to be dropped in front of existing apps with a single HTTP call
before the file is written to storage.

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
   - **PDF**: JavaScript (`/JavaScript`, `/JS`), `/Launch`, and **recursive inspection of attachments**
     (`/EmbeddedFile` — the attachment is extracted and validated; benign passes, an embedded
     exe/script/macro is caught). Covers FlateDecode streams.
   - **Office OOXML** (`docx`/`xlsx`): unzips and looks for DDE, macros (`vbaProject`), formula
     injection, and OLE objects.
   - **CSV**: formula/command injection per **OWASP** (cell starting with `=` `@` Tab, or `+`/`-`
     when it looks like a formula; `cmd|`, `WEBSERVICE`…).
   - **Images** (`jpg`/`png`): embedded `<script>`/`<?php` and data appended after the image end
     (polyglot).
   - **Legacy/HTML** (`doc`/`xls`): `<script>`, DDE, formulas, and macro markers.
3. **Antivirus** (optional): scan via **ClamAV** (open-source engine) using the `nClam` client.

> The active-content layer **detects and applies a policy — it does not sanitize** (not CDR).
> Encrypted/obfuscated payloads may evade it; full coverage requires CDR or a sandbox.

> **ClamAV is optional** (`FileScan:ClamAv:Enabled`): when disabled, the service runs only the
> structural + active-content layers — **no container/daemon required**.

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
    "verdict": "Clean",        // Clean | Malicious | Rejected
    "reason": null,            // populated when Malicious/Rejected
    "engine": "clamav",        // "clamav" or "filescan" (which layer decided)
    "scannedAtUtc": "2026-05-29T13:00:00.0000000Z"
  }
  ```
- **Response 503**: `verdict = "Error"` — the file could not be scanned (ClamAV down). The caller
  **must fail closed**. (Only happens when `ClamAv:Enabled=true`.)

**Caller's golden rule:** only persist the file if `HTTP 200` **and** `verdict == "Clean"`.

### `GET /health`
Liveness — the process is up.

### `GET /ready`
Readiness — ClamAV answers a ping (`200`) or not (`503`). Always `200` when ClamAV is disabled.

Interactive docs (Swagger UI) are served at `/swagger`.

---

## Configuration (`appsettings.json` → `FileScan` section)

| Key | Default | Description |
|---|---|---|
| `MaxFileSizeBytes` | `26214400` (25 MB) | Maximum accepted size |
| `AllowedExtensions` | `pdf,doc,docx,xls,xlsx,csv,jpg,jpeg,png` | Accepted extension allowlist; empty = no restriction |
| `ApiKey` | `""` | Requires the `X-Api-Key` header when set |
| `ClamAv:Enabled` | `true` | Enables the antivirus layer. `false` = structural + active-content only (**no container/daemon**) |
| `ClamAv:Host` / `ClamAv:Port` | `localhost` / `3310` | Address of the `clamd` daemon (when enabled) |
| `ActiveContent:OnDetected` | `Reject` | Active content (PDF/Office/CSV/images): `Reject`, `Flag` (passes + `warnings`), or `Ignore` |

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

Dependencies: **nClam** (Apache-2.0), **Mime-Detective** (MIT; *Default* definitions free for
commercial use), **Serilog** (Apache-2.0), **Swashbuckle** (MIT). **ClamAV** (GPLv2) runs as a
**separate** process/container — it is not linked into this project's code.
