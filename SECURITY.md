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
serves files back. A `Clean` verdict means *"no active-content/injection markers were
found"*, **not** *"safe to render inline in a browser"*.

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
serve o arquivo de volta. Um veredito `Clean` significa *"nenhum marcador de conteúdo
ativo/injeção foi encontrado"*, **não** *"pode renderizar inline no browser com segurança"*.

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

- **PDF name hex-encoding.** The PDF spec allows a name token's characters to be
  hex-escaped as `#XX` (e.g. `/J#53` ≡ `/JS`, `/#4Aavascript` ≡ `/Javascript`). The
  active-content marker search is a literal byte match, so a payload that hex-encodes
  the action name can slip past the PDF heuristic. Normalizing `#XX` in names before
  matching would close this; not yet implemented.
- **Non-Flate stream filters.** Active-content scanning covers raw bytes and
  **FlateDecode** streams. JavaScript hidden behind other filters (ASCIIHex, ASCII85,
  LZW, or chained filters) or inside an **encrypted** PDF is not inspected. Full
  coverage of these cases requires CDR or a sandbox.

### Evasões conhecidas / limitações — pt-BR

São lacunas conscientes da camada heurística; o ClamAV (quando habilitado) e as
responsabilidades de quem chama (acima) são as camadas complementares.

- **Hex-encoding de *names* de PDF.** A spec do PDF permite escapar os caracteres de um
  *name* como `#XX` (ex.: `/J#53` ≡ `/JS`, `/#4Aavascript` ≡ `/Javascript`). A busca de
  marcadores de conteúdo ativo é um match literal de bytes, então um payload que faz
  hex-encoding do nome da ação pode escapar da heurística de PDF. Normalizar `#XX` nos
  *names* antes do match fecharia isso; ainda não implementado.
- **Filtros de stream não-Flate.** O scan de conteúdo ativo cobre os bytes crus e os
  streams **FlateDecode**. JavaScript escondido atrás de outros filtros (ASCIIHex,
  ASCII85, LZW ou filtros encadeados) ou dentro de um PDF **criptografado** não é
  inspecionado. Cobertura total desses casos exige CDR ou sandbox.

## Reporting a vulnerability

If you find a security issue in FileScan itself (e.g. a way to bypass a check, a
crash/DoS, or a false-negative class), please **open a private report** via GitHub
Security Advisories, or open an issue **without** including a working malicious payload.

Please do **not** attach real malware or real user documents to public issues.

## Handling test samples

The `_testfiles/` directory contains **synthetic** proof-of-concept samples (benign
demonstrators such as `app.alert`, `calc`, EICAR, and `<?php echo>`). Do not add real
malware or real user data to this repository.
