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

- **Non-Flate stream filters.** PDF scanning covers the structural regions
  (dictionaries/objects, scanned raw) plus stream bodies that are either literal
  (no `/Filter`) or **FlateDecode** (always decompressed and scanned inflated —
  compressed bytes are never judged raw, since random compressed data produces
  false positives). JavaScript hidden behind other filters (ASCIIHex, ASCII85,
  LZW, or chained filters) or inside an **encrypted** PDF is not inspected —
  those bodies are skipped as uninterpretable. A crafted xref pointing into such
  a skipped body could hide an object from the heuristic. Full coverage of these
  cases requires CDR or a sandbox.

### Evasões conhecidas / limitações — pt-BR

São lacunas conscientes da camada heurística; o ClamAV (quando habilitado) e as
responsabilidades de quem chama (acima) são as camadas complementares.

- **Filtros de stream não-Flate.** O scan de PDF cobre as regiões estruturais
  (dicionários/objetos, varridas cruas) e os corpos de stream literais (sem `/Filter`)
  ou **FlateDecode** (sempre descomprimidos e varridos inflados — bytes comprimidos
  nunca são julgados crus, porque dados comprimidos aleatórios geram falso positivo).
  JavaScript escondido atrás de outros filtros (ASCIIHex, ASCII85, LZW ou filtros
  encadeados) ou dentro de um PDF **criptografado** não é inspecionado — esses corpos
  são pulados como ilegíveis. Um xref forjado apontando para dentro de um corpo pulado
  pode esconder um objeto da heurística. Cobertura total desses casos exige CDR ou
  sandbox.

## Reporting a vulnerability

If you find a security issue in FileScan itself (e.g. a way to bypass a check, a
crash/DoS, or a false-negative class), please **open a private report** via GitHub
Security Advisories, or open an issue **without** including a working malicious payload.

Please do **not** attach real malware or real user documents to public issues.

## Handling test samples

The `_testfiles/` directory contains **synthetic** proof-of-concept samples (benign
demonstrators such as `app.alert`, `calc`, EICAR, and `<?php echo>`). Do not add real
malware or real user data to this repository.
