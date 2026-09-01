# Security Policy

## Scope and limitations

FileScan performs **heuristic detection** of malicious / script-injection content in
uploaded files. It is **not** a certified CDR (Content Disarm & Reconstruction) product
and is **not** a replacement for a full antivirus or a certified commercial solution.

- It is a **defense-in-depth layer**, not a guarantee.
- Obfuscated/encrypted payloads and zero-day threats may evade detection.
- The optional ClamAV layer detects **known** malware only (signature-based).
- The software is provided **without warranty** (see [LICENSE](LICENSE)).

Always validate behavior in your own environment before relying on it.

## Caller responsibilities (serving uploaded files)

FileScan is **scan-only**: it inspects an upload and returns a verdict — it never
serves files back. For PDF/OOXML, `Clean` means the supported structural/active-content
inspection completed with no finding, warning, skipped work, exhausted budget or ambiguity.
It still does **not** mean *"malware-free"* or *"safe to render inline in a browser"*.

For the class of attack where a PDF (or other document) carries auto-running
JavaScript aimed at **stored XSS**, the strongest mitigations happen at **serving
time**, in the consuming application — FileScan cannot apply them. When you serve a
user-uploaded file to a browser, you **must**:

- Serve it as a download, not inline: `Content-Disposition: attachment; filename="..."`.
- Disable MIME sniffing: `X-Content-Type-Options: nosniff`.
- Send the correct, explicit `Content-Type` (e.g. `application/pdf`) — do not let the
  browser guess.
- Apply a restrictive Content-Security-Policy on the route that renders/embeds uploads,
  e.g. `Content-Security-Policy: script-src 'self'; object-src 'none'`.
- Prefer serving user uploads from a **separate origin/sandbox domain** (no session
  cookies) so that even a rendered payload cannot reach the main app's context.

Treating a `Clean` verdict as a license to render the file inline on the application's
own origin re-introduces the stored-XSS risk that FileScan reduced.

### Responsabilidades de quem chama (ao servir os arquivos) — pt-BR

O FileScan **apenas escaneia**: ele inspeciona o upload e devolve um veredito — nunca
serve o arquivo. Para PDF/OOXML, `Clean` significa que a inspeção estrutural/conteúdo ativo
suportada terminou sem achado, warning, trabalho pulado, orçamento esgotado ou ambiguidade.
Ainda **não** significa *"sem malware"* nem *"pode renderizar inline com segurança"*.

Para a classe de ataque em que um PDF (ou outro documento) carrega JavaScript de
auto-execução visando **stored XSS**, as mitigações mais fortes acontecem no momento de
**servir** o arquivo, no app consumidor — o FileScan não tem como aplicá-las. Ao entregar
um arquivo enviado por usuário a um browser, você **deve**:

- Servir como download, não inline: `Content-Disposition: attachment; filename="..."`.
- Desligar o MIME sniffing: `X-Content-Type-Options: nosniff`.
- Mandar o `Content-Type` correto e explícito (ex.: `application/pdf`) — não deixar o
  browser adivinhar.
- Aplicar uma Content-Security-Policy restritiva na rota que renderiza/embute uploads,
  ex.: `Content-Security-Policy: script-src 'self'; object-src 'none'`.
- De preferência, servir uploads de usuário a partir de uma **origem/domínio sandbox
  separado** (sem cookies de sessão), para que mesmo um payload renderizado não alcance
  o contexto do app principal.

Tratar um veredito `Clean` como licença para renderizar o arquivo inline na própria
origem da aplicação reintroduz o risco de stored XSS que o FileScan reduziu.

## Known evasions / limitations

These are conscious gaps in the heuristic layer; ClamAV (when enabled) and the caller
responsibilities above are the complementary layers.

- **Non-Flate stream filters.** PDF scanning covers the structural regions
  through PdfPig (xref/trailer, indirect references and object streams), plus stream bodies that are literal
  (no `/Filter`) or **FlateDecode** (always decompressed and scanned inflated —
  compressed bytes are never judged raw, since random compressed data produces
  false positives). Bodies behind other filters (ASCIIHex, ASCII85, LZW, or
  chained filters), inside an **encrypted** PDF, in a structurally invalid file,
  behind an unsupported predictor, or past per-stream/aggregate entry, expansion,
  attachment-count or recursion limits are **not silently skipped**: the scan returns
  `NotInspected` (never `Clean`) so the caller fails closed. Actually *reading*
  those bodies would require CDR or a sandbox.
  Embedded files are identified through `FileSpec` associations (`EmbeddedFiles`, `AF`, and `FS`
  inside `/Subtype /FileAttachment` annotations) and direct or indirect `/EF` relations; the
  optional `/Type /EmbeddedFile` marker is not trusted as the sole source. Unrelated `/EF` or `/FS`
  extension keys are ignored. Invalid name-tree values (including `/Limits` on the root node) and
  broken/cyclic/non-stream associated targets return `NotInspected`. Literal and hexadecimal name
  keys and child `/Limits` are compared by decoded bytes. Cancellation propagates through parsing
  and decompression.
- **The "full inspection or `NotInspected`" guarantee covers PDF and OOXML only.**
  For legacy OLE2 (`.doc`/`.xls`), images, CSV and plain text the engine is a
  best-effort byte-scanning heuristic and never reports incomplete inspection:
  `Clean` there means "no marker matched", not "fully parsed". An obfuscated or
  compressed OLE2 VBA macro can evade the raw scan and still come back `Clean` —
  if you accept OLE2 uploads, plug in an antivirus (`IVirusScanner`) or block
  those extensions via `AllowedExtensions`.

### Evasões conhecidas / limitações — pt-BR

São lacunas conscientes da camada heurística; o ClamAV (quando habilitado) e as
responsabilidades de quem chama (acima) são as camadas complementares.

- **Filtros de stream não-Flate.** O scan de PDF cobre as regiões estruturais
  via PdfPig (xref/trailer, referências indiretas e object streams) e os corpos de stream
  literais (sem `/Filter`) ou
  **FlateDecode** (sempre descomprimidos e varridos inflados — bytes comprimidos
  nunca são julgados crus, porque dados comprimidos aleatórios geram falso positivo).
  Corpos atrás de outros filtros (ASCIIHex, ASCII85, LZW ou filtros encadeados),
  com predictor não suportado, dentro de PDF **criptografado**, em estrutura inválida ou além dos
  limites por stream/agregados de entradas, expansão, anexos ou profundidade **não são pulados
  em silêncio**: o scan devolve
  `NotInspected` (nunca `Clean`) e o chamador falha fechado. LER esses corpos de fato
  exigiria CDR ou sandbox.
  Arquivos embutidos são identificados por associações `FileSpec` (`EmbeddedFiles`, `AF` e `FS`
  dentro de annotations `/Subtype /FileAttachment`) e relações `/EF` diretas ou indiretas; o
  marcador opcional `/Type /EmbeddedFile` não é a única fonte. Chaves de extensão `/EF` ou `/FS`
  sem esse contexto são ignoradas. Valores inválidos na name tree (inclusive `/Limits` no nó raiz)
  e alvos associados quebrados, cíclicos ou que não sejam stream devolvem `NotInspected`. Chaves e
  `/Limits` literais ou hexadecimais são comparados pelos bytes decodificados. Cancelamento é
  propagado por parsing e descompressão.
- **A garantia "inspeção integral ou `NotInspected`" cobre só PDF e OOXML.**
  Para OLE2 legado (`.doc`/`.xls`), imagens, CSV e texto puro o motor é heurística
  best-effort de varredura de bytes e nunca reporta inspeção incompleta: `Clean`
  nesses formatos significa "nenhum marcador casou", não "parseado por completo".
  Uma macro VBA OLE2 ofuscada ou comprimida pode evadir a varredura crua e ainda
  voltar `Clean` — se você aceita uploads OLE2, plugue um antivírus (`IVirusScanner`)
  ou bloqueie essas extensões via `AllowedExtensions`.

## Reporting a vulnerability

If you find a security issue in FileScan itself (e.g. a way to bypass a check, a
crash/DoS, or a false-negative class), please **open a private report** via GitHub
Security Advisories, or open an issue **without** including a working malicious payload.

Please do **not** attach real malware or real user documents to public issues.

## Handling test samples

The `_testfiles/` directory contains **synthetic** proof-of-concept samples (benign
demonstrators such as `app.alert`, `calc`, EICAR, and `<?php echo>`). Do not add real
malware or real user data to this repository.
